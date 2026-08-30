pub mod camouflage_site;
pub mod cert_reloader;
pub mod certificate_lifecycle;
pub mod gate;
pub mod limiter;
pub mod manager;
pub mod nginx_sni;
pub mod nginx_sni_traffic;
pub mod outbound;
pub mod selector;
// v1.0.8: Linux-only splice(2) zero-copy forwarding (used by tcp.rs for
// unlimited rules). Other targets fall back to the userspace copy.
#[cfg(target_os = "linux")]
pub mod splice;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod ws;

pub use manager::ForwarderManager;
