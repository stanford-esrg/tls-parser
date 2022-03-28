use nom::multi::length_data;
use nom::number::streaming::be_u16;
use nom::IResult;
use nom_derive::*;

/// Server Diffie-Hellman parameters, defined in [RFC5246] section 7.4.3
#[derive(PartialEq, NomBE, Hash)]
pub struct ServerDHParams<'a> {
    /// The prime modulus used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_p: &'a [u8],
    /// The generator used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_g: &'a [u8],
    /// The server's Diffie-Hellman public value (g^X mod p).
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_ys: &'a [u8],
}

#[inline]
pub fn parse_server_dh_params(i: &[u8]) -> IResult<&[u8], ServerDHParams> {
    ServerDHParams::parse(i)
}

/// Client Diffie-Hellman parameters, defined in [RFC5246] section 7.4.7.2
#[derive(PartialEq, NomBE, Hash)]
pub struct ClientDHPublic<'a> {
    /// The client's Diffie-Hellman public value.
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_yc: &'a [u8],
}

#[inline]
pub fn parse_client_dh_params(i: &[u8]) -> IResult<&[u8], ClientDHPublic> {
    ClientDHPublic::parse(i)
}
