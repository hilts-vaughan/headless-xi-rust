use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use blowfish::Blowfish;
use byteorder::{ByteOrder, LittleEndian};
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use md5::{Digest, Md5};
use thiserror::Error;

const IXFF: u32 = 0x4646_5849;
const HEADER_LEN: usize = 8;
const HASH_LEN: usize = 16;
const KEY_TRAILER_LEN: usize = 4;
const SEARCH_REQUEST_LEN: usize = 0x30;
const MAX_PACKET_LEN: usize = 4096;

const TCP_SEARCH_ALL: u8 = 0x00;

const SEARCH_NAME: u64 = 0x00;
const SEARCH_AREA: u64 = 0x01;
const SEARCH_NATION: u64 = 0x02;
const SEARCH_JOB: u64 = 0x03;
const SEARCH_LEVEL: u64 = 0x04;
const SEARCH_RACE: u64 = 0x05;
const SEARCH_FLAGS1: u64 = 0x06;
const SEARCH_ID: u64 = 0x08;
const SEARCH_UNK0X0E: u64 = 0x0E;
const SEARCH_RANK: u64 = 0x10;
const SEARCH_COMMENT: u64 = 0x11;
const SEARCH_FLAGS2: u64 = 0x16;
const SEARCH_LANGUAGE: u64 = 0x17;

const INITIAL_KEY: [u8; 24] = [
    0x30, 0x73, 0x3D, 0x6D, 0x3C, 0x31, 0x49, 0x5A, 0x32, 0x7A, 0x42, 0x43, 0x63, 0x38, 0x7B, 0x7E,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid packet: {0}")]
    InvalidPacket(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlinePlayer {
    pub id: Option<u32>,
    pub name: String,
    pub zone: Option<u16>,
    pub nation: Option<u8>,
    pub main_job: Option<u8>,
    pub main_level: Option<u8>,
    pub sub_job: Option<u8>,
    pub sub_level: Option<u8>,
    pub race: Option<u8>,
    pub rank: Option<u8>,
    pub flags1: Option<u32>,
    pub flags2: Option<u32>,
    pub languages: Option<u16>,
}

impl OnlinePlayer {
    fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            zone: None,
            nation: None,
            main_job: None,
            main_level: None,
            sub_job: None,
            sub_level: None,
            race: None,
            rank: None,
            flags1: None,
            flags2: None,
            languages: None,
        }
    }
}

pub struct SearchClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl SearchClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn list_online_players(&self) -> Result<Vec<OnlinePlayer>, SearchError> {
        let mut stream = TcpStream::connect_timeout(&self.addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let mut crypto = SearchCrypto::new();
        let request = crypto.encrypt(build_sea_all_request())?;
        stream.write_all(&request)?;

        let mut players = Vec::new();
        loop {
            let packet = read_packet(&mut stream)?;
            let decoded = crypto.decrypt(packet)?;
            let response = parse_search_list_packet(&decoded)?;
            players.extend(response.players);
            if response.final_packet {
                break;
            }
        }

        Ok(players)
    }
}

pub fn list_online_players(addr: SocketAddr) -> Result<Vec<OnlinePlayer>, SearchError> {
    SearchClient::new(addr).list_online_players()
}

fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, SearchError> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix)?;
    let len = LittleEndian::read_u16(&prefix) as usize;
    if !(28..=MAX_PACKET_LEN).contains(&len) {
        return Err(SearchError::InvalidPacket(format!("bad length {len}")));
    }

    let mut packet = vec![0u8; len];
    packet[..2].copy_from_slice(&prefix);
    stream.read_exact(&mut packet[2..])?;
    Ok(packet)
}

fn build_sea_all_request() -> Vec<u8> {
    let mut packet = vec![0u8; SEARCH_REQUEST_LEN];
    LittleEndian::write_u16(&mut packet[0..2], SEARCH_REQUEST_LEN as u16);
    LittleEndian::write_u32(&mut packet[4..8], IXFF);
    packet[0x0b] = TCP_SEARCH_ALL;
    packet
}

struct SearchCrypto {
    key: [u8; 24],
}

impl SearchCrypto {
    fn new() -> Self {
        Self { key: INITIAL_KEY }
    }

    fn encrypt(&mut self, mut packet: Vec<u8>) -> Result<Vec<u8>, SearchError> {
        let len = packet.len();
        if len < 28 {
            return Err(SearchError::InvalidPacket(
                "packet too short to encrypt".into(),
            ));
        }

        LittleEndian::write_u16(&mut packet[0..2], len as u16);
        LittleEndian::write_u32(&mut packet[4..8], IXFF);

        let digest = md5_bytes(&self.key[..20]);
        let hash_start = len - HASH_LEN - KEY_TRAILER_LEN;
        let hash = md5_bytes(&packet[HEADER_LEN..hash_start]);
        packet[hash_start..hash_start + HASH_LEN].copy_from_slice(&hash);

        blowfish_crypt(&mut packet, len, &digest, Direction::Encrypt)?;
        packet[len - KEY_TRAILER_LEN..].copy_from_slice(&self.key[16..20]);
        Ok(packet)
    }

    fn decrypt(&mut self, mut packet: Vec<u8>) -> Result<Vec<u8>, SearchError> {
        let len = packet.len();
        if len < 28 {
            return Err(SearchError::InvalidPacket(
                "packet too short to decrypt".into(),
            ));
        }

        self.key[16..20].copy_from_slice(&packet[len - KEY_TRAILER_LEN..]);
        let digest = md5_bytes(&self.key[..20]);
        blowfish_crypt(&mut packet, len, &digest, Direction::Decrypt)?;
        validate_hash(&packet)?;
        self.key[20..24].copy_from_slice(&packet[len - 0x18..len - 0x14]);
        Ok(packet)
    }
}

enum Direction {
    Encrypt,
    Decrypt,
}

fn blowfish_crypt(
    packet: &mut [u8],
    len: usize,
    key: &[u8; 16],
    direction: Direction,
) -> Result<(), SearchError> {
    let cipher = Blowfish::<byteorder::LE>::new_from_slice(key)
        .map_err(|err| SearchError::Crypto(format!("invalid blowfish key: {err}")))?;
    let mut words = (len - 12) / 4;
    words -= words % 2;

    for i in (0..words).step_by(2) {
        let start = (i + 2) * 4;
        let end = start + 8;
        if end > packet.len() {
            break;
        }
        let block = cipher::generic_array::GenericArray::from_mut_slice(&mut packet[start..end]);
        match direction {
            Direction::Encrypt => cipher.encrypt_block(block),
            Direction::Decrypt => cipher.decrypt_block(block),
        }
    }
    Ok(())
}

fn validate_hash(packet: &[u8]) -> Result<(), SearchError> {
    let len = packet.len();
    let hash_start = len - HASH_LEN - KEY_TRAILER_LEN;
    let expected = md5_bytes(&packet[HEADER_LEN..hash_start]);
    if packet[hash_start..hash_start + HASH_LEN] != expected {
        return Err(SearchError::InvalidPacket("MD5 validation failed".into()));
    }
    Ok(())
}

fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

struct SearchListResponse {
    final_packet: bool,
    players: Vec<OnlinePlayer>,
}

fn parse_search_list_packet(packet: &[u8]) -> Result<SearchListResponse, SearchError> {
    if packet.len() < 0x20 {
        return Err(SearchError::InvalidPacket(
            "search list packet too short".into(),
        ));
    }
    if packet[0x0b] != 0x80 {
        return Err(SearchError::InvalidPacket(format!(
            "unexpected response type 0x{:02x}",
            packet[0x0b]
        )));
    }

    let data_len = LittleEndian::read_u16(&packet[0x08..0x0a]) as usize;
    let payload_end = data_len.min(packet.len().saturating_sub(HASH_LEN + KEY_TRAILER_LEN));
    let mut offset = 192usize;
    let mut players = Vec::new();

    while offset / 8 < payload_end {
        let size_offset = offset / 8;
        let entity_size = packet[size_offset] as usize;
        if entity_size == 0 {
            break;
        }
        let entity_end = (size_offset + entity_size + 1) * 8;
        offset += 8;
        players.push(parse_player(packet, &mut offset, entity_end)?);
        offset = entity_end;
    }

    Ok(SearchListResponse {
        final_packet: packet[0x0a] & 0x80 != 0,
        players,
    })
}

fn parse_player(
    packet: &[u8],
    offset: &mut usize,
    entity_end_bits: usize,
) -> Result<OnlinePlayer, SearchError> {
    let mut player = OnlinePlayer::new();
    while *offset + 5 <= entity_end_bits {
        let entry = unpack_bits_le(packet, *offset, 5);
        *offset += 5;

        match entry {
            SEARCH_NAME => {
                let len = unpack_bits_le(packet, *offset, 4) as usize;
                *offset += 4;
                if len == 0 && !player.name.is_empty() {
                    break;
                }
                let mut name = String::with_capacity(len);
                for _ in 0..len {
                    name.push((unpack_bits_le(packet, *offset, 7) as u8) as char);
                    *offset += 7;
                }
                player.name = name;
            }
            SEARCH_AREA => {
                player.zone = Some(unpack_bits_le(packet, *offset, 10) as u16);
                *offset += 10;
            }
            SEARCH_NATION => {
                player.nation = Some(unpack_bits_le(packet, *offset, 2) as u8);
                *offset += 2;
            }
            SEARCH_JOB => {
                player.main_job = Some(unpack_bits_le(packet, *offset, 5) as u8);
                *offset += 5;
                player.sub_job = Some(unpack_bits_le(packet, *offset, 5) as u8);
                *offset += 5;
            }
            SEARCH_LEVEL => {
                player.main_level = Some(unpack_bits_le(packet, *offset, 8) as u8);
                *offset += 8;
                player.sub_level = Some(unpack_bits_le(packet, *offset, 8) as u8);
                *offset += 8;
            }
            SEARCH_RACE => {
                player.race = Some(unpack_bits_le(packet, *offset, 4) as u8);
                *offset += 4;
            }
            SEARCH_RANK => {
                player.rank = Some(unpack_bits_le(packet, *offset, 8) as u8);
                *offset += 8;
            }
            SEARCH_FLAGS1 => {
                player.flags1 = Some(unpack_bits_le(packet, *offset, 16) as u32);
                *offset += 16;
            }
            SEARCH_ID => {
                player.id = Some(unpack_bits_le(packet, *offset, 20) as u32);
                *offset += 20;
            }
            SEARCH_UNK0X0E | SEARCH_COMMENT | SEARCH_FLAGS2 => {
                let value = unpack_bits_le(packet, *offset, 32) as u32;
                if entry == SEARCH_FLAGS2 {
                    player.flags2 = Some(value);
                }
                *offset += 32;
            }
            SEARCH_LANGUAGE => {
                player.languages = Some(unpack_bits_le(packet, *offset, 16) as u16);
                *offset += 16;
            }
            _ => {
                return Err(SearchError::InvalidPacket(format!(
                    "unknown search entry {entry:#x}"
                )))
            }
        }
    }

    if player.name.is_empty() {
        return Err(SearchError::InvalidPacket(
            "player entry missing name".into(),
        ));
    }
    Ok(player)
}

fn unpack_bits_le(buf: &[u8], bit_offset: usize, width: usize) -> u64 {
    let mut value = 0u64;
    for bit in 0..width {
        let absolute = bit_offset + bit;
        let byte = buf.get(absolute / 8).copied().unwrap_or_default();
        let set = (byte >> (absolute % 8)) & 1;
        value |= u64::from(set) << bit;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_bits_le(buf: &mut [u8], mut bit_offset: usize, value: u64, width: usize) -> usize {
        for bit in 0..width {
            let absolute = bit_offset + bit;
            let byte = absolute / 8;
            let bit_in_byte = absolute % 8;
            if ((value >> bit) & 1) != 0 {
                buf[byte] |= 1 << bit_in_byte;
            }
        }
        bit_offset += width;
        bit_offset
    }

    #[test]
    fn sea_all_request_sets_minimal_search_all_body() {
        let packet = build_sea_all_request();
        assert_eq!(
            LittleEndian::read_u16(&packet[0..2]),
            SEARCH_REQUEST_LEN as u16
        );
        assert_eq!(LittleEndian::read_u32(&packet[4..8]), IXFF);
        assert_eq!(packet[0x0b], TCP_SEARCH_ALL);
        assert_eq!(packet[0x10], 0);
    }

    #[test]
    fn parses_bitpacked_search_player() {
        let mut packet = vec![0u8; 256];
        packet[0x0a] = 0x80;
        packet[0x0b] = 0x80;
        LittleEndian::write_u16(&mut packet[0x0e..0x10], 1);

        let size_offset = 192 / 8;
        let mut offset = 200;
        offset = pack_bits_le(&mut packet, offset, SEARCH_NAME, 5);
        offset = pack_bits_le(&mut packet, offset, 4, 4);
        for b in b"Test" {
            offset = pack_bits_le(&mut packet, offset, u64::from(*b), 7);
        }
        offset = pack_bits_le(&mut packet, offset, SEARCH_AREA, 5);
        offset = pack_bits_le(&mut packet, offset, 230, 10);
        offset = pack_bits_le(&mut packet, offset, SEARCH_JOB, 5);
        offset = pack_bits_le(&mut packet, offset, 1, 5);
        offset = pack_bits_le(&mut packet, offset, 2, 5);
        offset = pack_bits_le(&mut packet, offset, SEARCH_LEVEL, 5);
        offset = pack_bits_le(&mut packet, offset, 75, 8);
        offset = pack_bits_le(&mut packet, offset, 37, 8);
        offset = pack_bits_le(&mut packet, offset, SEARCH_ID, 5);
        offset = pack_bits_le(&mut packet, offset, 12345, 20);
        if offset % 8 != 0 {
            offset += 8 - offset % 8;
        }
        packet[size_offset] = (offset / 8 - size_offset - 1) as u8;
        LittleEndian::write_u16(&mut packet[0x08..0x0a], (offset / 8) as u16);

        let response = parse_search_list_packet(&packet).unwrap();
        assert!(response.final_packet);
        assert_eq!(response.players.len(), 1);
        assert_eq!(response.players[0].name, "Test");
        assert_eq!(response.players[0].zone, Some(230));
        assert_eq!(response.players[0].main_job, Some(1));
        assert_eq!(response.players[0].sub_job, Some(2));
        assert_eq!(response.players[0].main_level, Some(75));
        assert_eq!(response.players[0].sub_level, Some(37));
        assert_eq!(response.players[0].id, Some(12345));
    }

    #[test]
    fn encrypted_sea_all_request_validates_after_local_decrypt() {
        let mut writer = SearchCrypto::new();
        let encrypted = writer.encrypt(build_sea_all_request()).unwrap();

        let mut reader = SearchCrypto::new();
        let decrypted = reader.decrypt(encrypted).unwrap();

        assert_eq!(decrypted[0x0b], TCP_SEARCH_ALL);
        assert_eq!(decrypted[0x10], 0);
    }
}
