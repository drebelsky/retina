use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Serialize, Debug, PartialEq, Clone)]
pub enum Category {
    AS32,
    Other,
}

pub type Table = IpNetworkTable<Category>;

pub fn create_table() -> Table {
    let mut table = IpNetworkTable::new();
    assert_eq!(
        table.insert(
            IpNetwork::new(Ipv4Addr::new(128, 12, 0, 0), 16).unwrap(),
            Category::AS32
        ),
        None
    );
    assert_eq!(
        table.insert(
            IpNetwork::new(Ipv4Addr::new(171, 64, 0, 0), 14).unwrap(),
            Category::AS32
        ),
        None
    );
    assert_eq!(
        table.insert(
            IpNetwork::new(Ipv4Addr::new(171, 67, 232, 160), 28).unwrap(),
            Category::AS32
        ),
        None
    );
    assert_eq!(
        table.insert(
            IpNetwork::new(Ipv4Addr::new(204, 63, 224, 0), 21).unwrap(),
            Category::AS32
        ),
        None
    );
    table
}

pub fn categorize(ip: IpAddr, table: &Table) -> Category {
    match ip {
        IpAddr::V4(_) => {
            return match table.longest_match(ip) {
                Some((_, asn)) => asn.clone(),
                None => Category::Other,
            }
        }
        IpAddr::V6(_) => Category::Other,
    }
}
