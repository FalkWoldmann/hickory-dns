use std::{borrow::Cow, collections::HashMap, fs, net::IpAddr, path::Path, str::FromStr};

use hickory_proto::ProtoError;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
};
use tracing::{debug, warn};

use super::sanitize::parse_search_domains;
use super::unix::parse_resolv_conf;
use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts, ScopedConfig};
use crate::net::NetError;
use crate::proto::rr::Name;

const GLOBAL_DNS_KEY: &str = "State:/Network/Global/DNS";
const SERVICE_DNS_KEYS: &str = "State:/Network/Service/[^/]+/DNS";
const RESOLVER_DIR: &str = "/etc/resolver";

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let sc = dynamic_store()?;
    let config = global_config(&dns_dictionary(&sc, GLOBAL_DNS_KEY)?)?;
    Ok((config, ResolverOpts::default()))
}

/// Reads the system configuration including the resolvers scoped to domains: the supplemental
/// resolvers of the network services in the System Configuration (as `scutil --dns` lists them)
/// and the files under `/etc/resolver`, a file winning over a service entry for the same domain.
pub fn read_scoped_system_conf() -> Result<(ScopedConfig, ResolverOpts), ProtoError> {
    let sc = dynamic_store()?;
    let mut config = ScopedConfig::new(global_config(&dns_dictionary(&sc, GLOBAL_DNS_KEY)?)?);
    for key in sc.get_keys(SERVICE_DNS_KEYS).iter().flatten() {
        match dns_dictionary(&sc, key.clone()) {
            Ok(dns_cfg) => config.scopes.extend(supplemental_scopes(&dns_cfg)),
            Err(e) => debug!(key = %*key, error = %e, "ignoring service DNS entry"),
        }
    }
    config
        .scopes
        .extend(resolver_dir_scopes(Path::new(RESOLVER_DIR)));
    Ok((config, ResolverOpts::default()))
}

fn dynamic_store() -> Result<SCDynamicStore, ProtoError> {
    SCDynamicStoreBuilder::new("hickory-resolver")
        .build()
        .ok_or_else(|| "failed to access System Configuration dynamic store".into())
}

fn dns_dictionary(
    sc: &SCDynamicStore,
    key: impl Into<CFString>,
) -> Result<CFDictionary, ProtoError> {
    sc.get(key)
        .ok_or("no DNS information in System Configuration")?
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| "DNS object in System Configuration is not a CFDictionary".into())
}

fn global_config(dns_cfg: &CFDictionary) -> Result<ResolverConfig, ProtoError> {
    let name_servers = name_servers(dns_cfg)?;

    let mut search_domains = vec![];
    if let Some(search_domains_cf) = string_array(dns_cfg, "SearchDomains") {
        for s in &*search_domains_cf {
            for domain in parse_search_domains(&Cow::from(&*s)) {
                search_domains.push(domain?);
            }
        }
    }

    Ok(ResolverConfig::from_parts(
        None,
        search_domains,
        name_servers,
    ))
}

/// Returns the scopes of a network service's DNS entry, which `SupplementalMatchDomains` marks as
/// serving only those domains.
///
/// <https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnssupplementalmatchdomains-swift.var>
fn supplemental_scopes(dns_cfg: &CFDictionary) -> Vec<(Name, ResolverConfig)> {
    let Some(domains_cf) = string_array(dns_cfg, "SupplementalMatchDomains") else {
        return vec![];
    };
    let name_servers = match name_servers(dns_cfg) {
        Ok(name_servers) => name_servers,
        Err(e) => {
            warn!(error = %e, "ignoring supplemental resolver");
            return vec![];
        }
    };

    let mut scopes = Vec::with_capacity(domains_cf.len() as usize);
    for s in &*domains_cf {
        for domain in parse_search_domains(&Cow::from(&*s)) {
            match domain {
                Ok(domain) => scopes.push((
                    domain,
                    ResolverConfig::from_name_servers(name_servers.clone()),
                )),
                Err(e) => warn!(error = %e, "ignoring unparseable supplemental match domain"),
            }
        }
    }
    scopes
}

fn name_servers(dns_cfg: &CFDictionary) -> Result<Vec<NameServerConfig>, ProtoError> {
    // A local DNS proxy (as VPN clients install) may listen on a port other than 53.
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserverport
    let port = dns_cfg
        .find(CFString::from_static_string("ServerPort").as_CFTypeRef())
        .and_then(|port_cf| {
            let port_cf: ItemRef<'_, CFNumber> = unsafe { CFNumber::from_void(*port_cf) };
            match u16::try_from(port_cf.to_i64()?) {
                Ok(0) | Err(_) => None,
                Ok(port) => Some(port),
            }
        });

    let nameservers_cf =
        string_array(dns_cfg, "ServerAddresses").ok_or("no ServerAddresses key in DNS info")?;

    let mut nameservers = Vec::with_capacity(nameservers_cf.len() as usize);
    for n in &*nameservers_cf {
        let s = Cow::from(&*n);
        // macOS reports link-local nameservers with a zone id (e.g. `fe80::1%en0`),
        // which `IpAddr::from_str` cannot parse. Strip the zone and keep the base
        // address, matching the `resolv.conf` path (see `resolv_conf::ScopedIp`).
        let stripped = match s.split_once('%') {
            Some((addr, _zone)) => addr,
            None => &*s,
        };
        let addr = match IpAddr::from_str(stripped) {
            Ok(addr) => addr,
            Err(e) => {
                warn!(
                    nameserver = %s,
                    error = %e,
                    "ignoring unparseable nameserver"
                );
                continue;
            }
        };
        let mut nameserver = NameServerConfig::udp_and_tcp(addr);
        if let Some(port) = port {
            for connection in &mut nameserver.connections {
                connection.port = port;
            }
        }
        nameservers.push(nameserver);
    }
    Ok(nameservers)
}

/// Looks up `key`, which Apple documents as a `CFArray` of `CFString`s.
///
/// <https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserveraddresses-swift.var>
/// <https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnssearchdomains-swift.var>
fn string_array<'a>(
    dns_cfg: &'a CFDictionary,
    key: &'static str,
) -> Option<ItemRef<'a, CFArray<CFString>>> {
    let value = dns_cfg.find(CFString::from_static_string(key).as_CFTypeRef())?;
    Some(unsafe { CFArray::from_void(*value) })
}

/// Reads the resolvers in `dir`, where each file is named after the domain it serves and holds
/// `resolv.conf` directives plus those of `resolver(5)`.
fn resolver_dir_scopes(dir: &Path) -> HashMap<Name, ResolverConfig> {
    let mut scopes = HashMap::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!(dir = %dir.display(), error = %e, "no resolver directory");
            return scopes;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match read_resolver_file(&path) {
            Ok((domain, config)) => {
                scopes.insert(domain, config);
            }
            Err(e) => warn!(path = %path.display(), error = %e, "ignoring resolver file"),
        }
    }
    scopes
}

/// Reads a `resolver(5)` file, whose `domain` names the domain it serves instead of the file name
fn read_resolver_file(path: &Path) -> Result<(Name, ResolverConfig), NetError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("file name is not a domain")?;

    let data = fs::read_to_string(path)?;
    let (apple, resolv_conf): (Vec<&str>, Vec<&str>) = data.lines().partition(|line| {
        matches!(
            line.split_whitespace().next(),
            Some("domain" | "port" | "search_order" | "timeout")
        )
    });
    let directive = |name: &str| {
        apple
            .iter()
            .find_map(|line| line.strip_prefix(name)?.split_whitespace().next())
    };

    let domain = Name::from_str_relaxed(directive("domain").unwrap_or(file_name))?;
    let (mut config, _) = parse_resolv_conf(resolv_conf.join("\n"))?;
    if let Some(port) = directive("port").and_then(|port| port.parse().ok()) {
        for connection in config
            .name_servers
            .iter_mut()
            .flat_map(|name_server| &mut name_server.connections)
        {
            connection.port = port;
        }
    }
    Ok((domain, config))
}

#[cfg(test)]
mod tests {
    use system_configuration::core_foundation::base::CFType;

    use super::*;

    fn dns_dict(pairs: &[(&'static str, CFType)]) -> CFDictionary {
        let pairs = pairs
            .iter()
            .map(|(key, value)| (CFString::from_static_string(key), value.clone()))
            .collect::<Vec<_>>();
        CFDictionary::from_CFType_pairs(&pairs).into_untyped()
    }

    fn strings(values: &[&str]) -> CFType {
        let values = values
            .iter()
            .map(|value| CFString::new(value))
            .collect::<Vec<_>>();
        CFArray::from_CFTypes(&values).into_CFType()
    }

    fn ips(config: &ResolverConfig) -> Vec<IpAddr> {
        config.name_servers.iter().map(|ns| ns.ip).collect()
    }

    fn ports(config: &ResolverConfig) -> Vec<u16> {
        config
            .name_servers
            .iter()
            .flat_map(|ns| &ns.connections)
            .map(|connection| connection.port)
            .collect()
    }

    #[test]
    fn global_config_from_dictionary() {
        let dns_cfg = dns_dict(&[
            (
                "SearchDomains",
                strings(&["fritz.box", "a.example b.example"]),
            ),
            (
                "ServerAddresses",
                strings(&["192.168.178.1", "fe80::1%en0"]),
            ),
        ]);
        let config = global_config(&dns_cfg).unwrap();
        assert_eq!(
            config.search,
            ["fritz.box", "a.example", "b.example"].map(|d| Name::from_str(d).unwrap())
        );
        assert_eq!(
            ips(&config),
            ["192.168.178.1", "fe80::1"].map(|ip| IpAddr::from_str(ip).unwrap())
        );
        assert_eq!(ports(&config), [53, 53, 53, 53]);

        let no_servers = dns_dict(&[("SearchDomains", strings(&["fritz.box"]))]);
        assert!(global_config(&no_servers).is_err());
    }

    #[test]
    fn supplemental_scopes_from_dictionary() {
        let dns_cfg = dns_dict(&[
            ("ServerAddresses", strings(&["100.100.100.100"])),
            ("ServerPort", CFNumber::from(5353).into_CFType()),
            (
                "SupplementalMatchDomains",
                strings(&["ts.net", "corp.example."]),
            ),
        ]);
        let scopes = supplemental_scopes(&dns_cfg);
        assert_eq!(
            scopes
                .iter()
                .map(|(domain, _)| domain.clone())
                .collect::<Vec<_>>(),
            ["ts.net", "corp.example."].map(|d| Name::from_str(d).unwrap())
        );
        for (_, config) in &scopes {
            assert_eq!(ips(config), [IpAddr::from([100, 100, 100, 100])]);
            assert_eq!(ports(config), [5353, 5353]);
        }

        let primary = dns_dict(&[("ServerAddresses", strings(&["192.168.178.1"]))]);
        assert!(supplemental_scopes(&primary).is_empty());
    }

    #[test]
    fn resolver_dir() {
        let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/resolver"));
        let scopes = resolver_dir_scopes(dir);
        assert_eq!(scopes.len(), 3);

        let ts_net = &scopes[&Name::from_str("ts.net").unwrap()];
        assert_eq!(ips(ts_net), [IpAddr::from([100, 100, 100, 100])]);
        assert_eq!(ports(ts_net), [53, 53]);

        let corp = &scopes[&Name::from_str("corp.example").unwrap()];
        assert_eq!(ips(corp), [IpAddr::from([10, 0, 0, 53])]);
        assert_eq!(ports(corp), [2053, 2053]);

        let containers = &scopes[&Name::from_str("test").unwrap()];
        assert_eq!(ips(containers), [IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(ports(containers), [2053, 2053]);

        assert!(resolver_dir_scopes(&dir.join("missing")).is_empty());
    }
}
