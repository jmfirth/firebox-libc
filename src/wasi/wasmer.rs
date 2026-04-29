// POSIX socket API for wasm32-wasmer-wasi (WASI preview 1 + WASIX extensions).
//
// Constants are emitted by the wasix-libc preprocessor against the
// firebox-wasix-libc fork; see the probe in
// `tools/wasix-const-probe/wasix_const_probe.c` for the source of truth.
// They are NEITHER Linux/musl values NOR wasi-p2 spec values — wasix-libc's
// cloudlibc layer has its own value scheme.
//
// extern fn declarations match the symbols that wasix-libc's libc.a exports
// (probed via `nm`); they are linked at runtime via cloudlibc's syscall
// thunks into wasmer-wasix's virtual-net layer.

use crate::prelude::*;

pub type sa_family_t = c_ushort;
pub type in_port_t = c_ushort;
pub type in_addr_t = c_uint;
pub type socklen_t = c_uint;

s! {
    #[repr(align(4))]
    pub struct sockaddr {
        pub sa_family: sa_family_t,
        pub sa_data: [c_char; 14],
    }

    pub struct in_addr {
        pub s_addr: in_addr_t,
    }

    #[repr(align(4))]
    pub struct sockaddr_in {
        pub sin_family: sa_family_t,
        pub sin_port: in_port_t,
        pub sin_addr: in_addr,
        pub sin_zero: [c_char; 8],
    }

    #[repr(align(4))]
    pub struct in6_addr {
        pub s6_addr: [c_uchar; 16],
    }

    #[repr(align(4))]
    pub struct sockaddr_in6 {
        pub sin6_family: sa_family_t,
        pub sin6_port: in_port_t,
        pub sin6_flowinfo: c_uint,
        pub sin6_addr: in6_addr,
        pub sin6_scope_id: c_uint,
    }

    #[repr(align(8))]
    pub struct sockaddr_storage {
        pub ss_family: sa_family_t,
        __ss_pad1: [c_char; 6],
        __ss_align: i64,
        __ss_pad2: [c_char; 112],
    }

    pub struct addrinfo {
        pub ai_flags: c_int,
        pub ai_family: c_int,
        pub ai_socktype: c_int,
        pub ai_protocol: c_int,
        pub ai_addrlen: socklen_t,
        pub ai_addr: *mut sockaddr,
        pub ai_canonname: *mut c_char,
        pub ai_next: *mut addrinfo,
    }

    pub struct ip_mreq {
        pub imr_multiaddr: in_addr,
        pub imr_interface: in_addr,
    }

    pub struct ipv6_mreq {
        pub ipv6mr_multiaddr: in6_addr,
        pub ipv6mr_interface: c_uint,
    }

    pub struct linger {
        pub l_onoff: c_int,
        pub l_linger: c_int,
    }

    pub struct msghdr {
        pub msg_name: *mut c_void,
        pub msg_namelen: socklen_t,
        pub msg_iov: *mut crate::iovec,
        pub msg_iovlen: c_int,
        pub msg_control: *mut c_void,
        pub msg_controllen: socklen_t,
        pub msg_flags: c_int,
    }
}

pub const AF_UNSPEC: c_int = 0;
pub const AF_INET: c_int = 1;
pub const AF_INET6: c_int = 2;
pub const AF_UNIX: c_int = 3;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
// SOCK_RDM is not defined by wasix-libc; callers gate via cfg(not(target_os = "wasi")).
pub const SOCK_SEQPACKET: c_int = 4;
pub const SOCK_NONBLOCK: c_int = 0x00004000;
pub const SOCK_CLOEXEC: c_int = 0x00002000;

pub const SOL_SOCKET: c_int = 0x7fffffff;

pub const SO_REUSEADDR: c_int = 2;
pub const SO_TYPE: c_int = 25;
pub const SO_ERROR: c_int = 11;
pub const SO_BROADCAST: c_int = 6;
pub const SO_SNDBUF: c_int = 16;
pub const SO_RCVBUF: c_int = 15;
pub const SO_KEEPALIVE: c_int = 12;
pub const SO_OOBINLINE: c_int = 14;
pub const SO_LINGER: c_int = 13;
pub const SO_REUSEPORT: c_int = 1;
pub const SO_RCVTIMEO: c_int = 19;
pub const SO_SNDTIMEO: c_int = 20;

pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPPROTO_ICMPV6: c_int = 58;

pub const IP_TOS: c_int = 1;
pub const IP_TTL: c_int = 2;
pub const IP_RECVTOS: c_int = 13;
pub const IP_MULTICAST_IF: c_int = 32;
pub const IP_MULTICAST_TTL: c_int = 33;
pub const IP_MULTICAST_LOOP: c_int = 34;
pub const IP_ADD_MEMBERSHIP: c_int = 35;
pub const IP_DROP_MEMBERSHIP: c_int = 36;

pub const IPV6_UNICAST_HOPS: c_int = 16;
pub const IPV6_MULTICAST_IF: c_int = 17;
pub const IPV6_MULTICAST_HOPS: c_int = 18;
pub const IPV6_MULTICAST_LOOP: c_int = 19;
pub const IPV6_JOIN_GROUP: c_int = 20;
pub const IPV6_LEAVE_GROUP: c_int = 21;
pub const IPV6_V6ONLY: c_int = 26;
pub const IPV6_RECVTCLASS: c_int = 66;
pub const IPV6_ADD_MEMBERSHIP: c_int = IPV6_JOIN_GROUP;
pub const IPV6_DROP_MEMBERSHIP: c_int = IPV6_LEAVE_GROUP;

pub const TCP_NODELAY: c_int = 1;
pub const TCP_KEEPIDLE: c_int = 4;
pub const TCP_KEEPINTVL: c_int = 5;
pub const TCP_KEEPCNT: c_int = 6;

pub const SHUT_RD: c_int = 1 << 0;
pub const SHUT_WR: c_int = 1 << 1;
pub const SHUT_RDWR: c_int = SHUT_RD | SHUT_WR;

pub const MSG_OOB: c_int = 0x0001;
pub const MSG_PEEK: c_int = 0x0002;
pub const MSG_TRUNC: c_int = 0x0020;
pub const MSG_EOR: c_int = 0x0080;
pub const MSG_WAITALL: c_int = 0x0100;
pub const MSG_NOSIGNAL: c_int = 0x4000;

pub const F_DUPFD: c_int = 5;
pub const F_DUPFD_CLOEXEC: c_int = 6;

pub const EAI_SYSTEM: c_int = -11;

extern "C" {
    pub fn socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int;
    pub fn connect(fd: c_int, name: *const sockaddr, addrlen: socklen_t) -> c_int;
    pub fn bind(socket: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int;
    pub fn listen(socket: c_int, backlog: c_int) -> c_int;
    pub fn accept(socket: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int;
    pub fn accept4(
        socket: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        flags: c_int,
    ) -> c_int;

    pub fn getsockname(socket: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int;
    pub fn getpeername(socket: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int;

    pub fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: size_t,
        flags: c_int,
        addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> ssize_t;
    pub fn recvfrom(
        socket: c_int,
        buffer: *mut c_void,
        length: size_t,
        flags: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
    ) -> ssize_t;

    pub fn recvmsg(socket: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t;
    pub fn sendmsg(socket: c_int, msg: *const msghdr, flags: c_int) -> ssize_t;

    pub fn getsockopt(
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut socklen_t,
    ) -> c_int;
    pub fn setsockopt(
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int;

    pub fn getaddrinfo(
        host: *const c_char,
        serv: *const c_char,
        hint: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int;
    pub fn freeaddrinfo(p: *mut addrinfo);
    pub fn gai_strerror(ecode: c_int) -> *const c_char;
}
