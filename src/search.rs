use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use byteorder::{ByteOrder, LittleEndian};
use md5::{Digest, Md5};
use thiserror::Error;

mod blowfish_consts;

const IXFF: u32 = 0x4646_5849;
const HEADER_LEN: usize = 8;
const HASH_LEN: usize = 16;
const KEY_TRAILER_LEN: usize = 4;
const SEARCH_REQUEST_LEN: usize = 0x4c;
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
            let packet = match read_packet(&mut stream) {
                Ok(packet) => packet,
                Err(SearchError::Io(err)) if players.is_empty() => return Err(err.into()),
                Err(SearchError::Io(err)) if is_timeout_error(&err) => break,
                Err(err) => return Err(err),
            };
            let decoded = crypto.decrypt(packet)?;
            dump_packet_if_requested(&decoded);
            let response = parse_search_list_packet(&decoded)?;
            players.extend(response.players);
            if response.final_packet {
                break;
            }
        }

        Ok(players)
    }
}

fn is_timeout_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
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
    LittleEndian::write_u16(&mut packet[0x08..0x0a], 0x13);
    packet[0x0a] = 0x80;
    packet[0x0b] = TCP_SEARCH_ALL;
    packet[0x10] = 0x02;
    packet[0x12] = 0x10;
    LittleEndian::write_u32(&mut packet[0x14..0x18], 60_000);
    LittleEndian::write_u32(&mut packet[0x18..0x1c], 60_000);
    LittleEndian::write_u32(&mut packet[0x1c..0x20], 3);
    LittleEndian::write_u32(&mut packet[0x20..0x24], 3);
    LittleEndian::write_u32(&mut packet[0x24..0x28], 0x10);
    LittleEndian::write_u32(&mut packet[0x30..0x34], 60_000);
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
        let digest = md5_bytes(&self.key);
        blowfish_crypt(&mut packet, len, &digest, Direction::Decrypt)?;
        validate_hash(&packet)?;
        self.key[20..24].copy_from_slice(&packet[len - 0x18..len - 0x14]);
        Ok(packet)
    }

    #[cfg(test)]
    fn decrypt_client_request_for_test(
        &mut self,
        mut packet: Vec<u8>,
    ) -> Result<Vec<u8>, SearchError> {
        let len = packet.len();
        self.key[16..20].copy_from_slice(&packet[len - KEY_TRAILER_LEN..]);
        let digest = md5_bytes(&self.key[..20]);
        blowfish_crypt(&mut packet, len, &digest, Direction::Decrypt)?;
        validate_hash(&packet)?;
        Ok(packet)
    }

    #[cfg(test)]
    fn encrypt_server_response_for_test(
        &mut self,
        mut packet: Vec<u8>,
    ) -> Result<Vec<u8>, SearchError> {
        let len = packet.len();
        LittleEndian::write_u16(&mut packet[0..2], len as u16);
        LittleEndian::write_u32(&mut packet[4..8], IXFF);

        let digest = md5_bytes(&self.key);
        let hash_start = len - HASH_LEN - KEY_TRAILER_LEN;
        let hash = md5_bytes(&packet[HEADER_LEN..hash_start]);
        packet[hash_start..hash_start + HASH_LEN].copy_from_slice(&hash);

        blowfish_crypt(&mut packet, len, &digest, Direction::Encrypt)?;
        packet[len - KEY_TRAILER_LEN..].copy_from_slice(&self.key[16..20]);
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
    let cipher = XiBlowfish::new(key);
    let mut words = (len - 12) / 4;
    words -= words % 2;

    for i in (0..words).step_by(2) {
        let start = (i + 2) * 4;
        let end = start + 8;
        if end > packet.len() {
            break;
        }
        let mut left = LittleEndian::read_u32(&packet[start..start + 4]);
        let mut right = LittleEndian::read_u32(&packet[start + 4..end]);
        match direction {
            Direction::Encrypt => cipher.encipher(&mut left, &mut right),
            Direction::Decrypt => cipher.decipher(&mut left, &mut right),
        }
        LittleEndian::write_u32(&mut packet[start..start + 4], left);
        LittleEndian::write_u32(&mut packet[start + 4..end], right);
    }
    Ok(())
}

struct XiBlowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl XiBlowfish {
    fn new(key: &[u8]) -> Self {
        let mut cipher = Self {
            p: blowfish_consts::P,
            s: blowfish_consts::S,
        };

        let mut key_index = 0;
        for p in &mut cipher.p {
            let mut data = 0u32;
            for _ in 0..4 {
                data = (data << 8) | ((key[key_index] as i8) as i32 as u32);
                key_index += 1;
                if key_index >= key.len() {
                    key_index = 0;
                }
            }
            *p ^= data;
        }

        let mut left = 0;
        let mut right = 0;
        for i in (0..18).step_by(2) {
            cipher.encipher(&mut left, &mut right);
            cipher.p[i] = left;
            cipher.p[i + 1] = right;
        }
        for i in 0..4 {
            for j in (0..256).step_by(2) {
                cipher.encipher(&mut left, &mut right);
                cipher.s[i][j] = left;
                cipher.s[i][j + 1] = right;
            }
        }

        cipher
    }

    fn encipher(&self, left: &mut u32, right: &mut u32) {
        let mut xl = *left;
        let mut xr = *right;

        for i in 0..16 {
            xl ^= self.p[i];
            xr ^= self.round(xl);
            std::mem::swap(&mut xl, &mut xr);
        }
        std::mem::swap(&mut xl, &mut xr);
        xr ^= self.p[16];
        xl ^= self.p[17];

        *left = xl;
        *right = xr;
    }

    fn decipher(&self, left: &mut u32, right: &mut u32) {
        let mut xl = *left;
        let mut xr = *right;

        for i in (2..=17).rev() {
            xl ^= self.p[i];
            xr ^= self.round(xl);
            std::mem::swap(&mut xl, &mut xr);
        }
        std::mem::swap(&mut xl, &mut xr);
        xr ^= self.p[1];
        xl ^= self.p[0];

        *left = xl;
        *right = xr;
    }

    fn round(&self, working: u32) -> u32 {
        let s = |index: usize| self.s[index / 256][index % 256];
        let a = ((working >> 8) & 0xff) as usize;
        let b = (working >> 24) as usize;
        let c = ((working >> 16) & 0xff) as usize;
        let d = (working & 0xff) as usize;

        ((s(256 + a) & 1) ^ 32)
            .wrapping_add((s(768 + b) & 1) ^ 32)
            .wrapping_add(s(512 + c))
            .wrapping_add(s(d))
    }
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

fn dump_packet_if_requested(packet: &[u8]) {
    if std::env::var_os("HEADLESS_XI_DUMP_PACKETS").is_none() {
        return;
    }

    eprintln!("decrypted packet ({} bytes):", packet.len());
    for chunk in packet.chunks(16) {
        for byte in chunk {
            eprint!("{byte:02x} ");
        }
        eprintln!();
    }
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
        let player_start = offset;
        let player =
            parse_player(packet, &mut offset, entity_end, BitOrder::Lsb).or_else(|_| {
                offset = player_start;
                parse_player(packet, &mut offset, entity_end, BitOrder::Msb)
            })?;
        if is_valid_player_name(&player.name) {
            players.push(player);
        }
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
    bit_order: BitOrder,
) -> Result<OnlinePlayer, SearchError> {
    let mut player = OnlinePlayer::new();
    while *offset + 5 <= entity_end_bits {
        let entry = unpack_bits(packet, *offset, 5, bit_order);
        *offset += 5;

        match entry {
            SEARCH_NAME => {
                let len = unpack_bits(packet, *offset, 4, bit_order) as usize;
                *offset += 4;
                if len == 0 && !player.name.is_empty() {
                    break;
                }
                let mut name = String::with_capacity(len);
                for _ in 0..len {
                    name.push((unpack_bits(packet, *offset, 7, bit_order) as u8) as char);
                    *offset += 7;
                }
                player.name = name;
            }
            SEARCH_AREA => {
                player.zone = Some(unpack_bits(packet, *offset, 10, bit_order) as u16);
                *offset += 10;
            }
            SEARCH_NATION => {
                player.nation = Some(unpack_bits(packet, *offset, 2, bit_order) as u8);
                *offset += 2;
            }
            SEARCH_JOB => {
                player.main_job = Some(unpack_bits(packet, *offset, 5, bit_order) as u8);
                *offset += 5;
                player.sub_job = Some(unpack_bits(packet, *offset, 5, bit_order) as u8);
                *offset += 5;
            }
            SEARCH_LEVEL => {
                player.main_level = Some(unpack_bits(packet, *offset, 8, bit_order) as u8);
                *offset += 8;
                player.sub_level = Some(unpack_bits(packet, *offset, 8, bit_order) as u8);
                *offset += 8;
            }
            SEARCH_RACE => {
                player.race = Some(unpack_bits(packet, *offset, 4, bit_order) as u8);
                *offset += 4;
            }
            SEARCH_RANK => {
                player.rank = Some(unpack_bits(packet, *offset, 8, bit_order) as u8);
                *offset += 8;
            }
            SEARCH_FLAGS1 => {
                player.flags1 = Some(unpack_bits(packet, *offset, 16, bit_order) as u32);
                *offset += 16;
            }
            SEARCH_ID => {
                player.id = Some(unpack_bits(packet, *offset, 20, bit_order) as u32);
                *offset += 20;
            }
            SEARCH_UNK0X0E | SEARCH_COMMENT | SEARCH_FLAGS2 => {
                let value = unpack_bits(packet, *offset, 32, bit_order) as u32;
                if entry == SEARCH_FLAGS2 {
                    player.flags2 = Some(value);
                }
                *offset += 32;
            }
            SEARCH_LANGUAGE => {
                player.languages = Some(unpack_bits(packet, *offset, 16, bit_order) as u16);
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

fn is_valid_player_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphabetic())
}

#[derive(Clone, Copy)]
enum BitOrder {
    Lsb,
    Msb,
}

fn unpack_bits(buf: &[u8], bit_offset: usize, width: usize, bit_order: BitOrder) -> u64 {
    match bit_order {
        BitOrder::Lsb => unpack_bits_le(buf, bit_offset, width),
        BitOrder::Msb => unpack_bits_msb(buf, bit_offset, width),
    }
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

fn unpack_bits_msb(buf: &[u8], bit_offset: usize, width: usize) -> u64 {
    let mut value = 0u64;
    for bit in 0..width {
        let absolute = bit_offset + bit;
        let byte = buf.get(absolute / 8).copied().unwrap_or_default();
        let set = (byte >> (7 - (absolute % 8))) & 1;
        value = (value << 1) | u64::from(set);
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
    fn sea_all_request_matches_captured_search_all_body() {
        let packet = build_sea_all_request();
        assert_eq!(
            LittleEndian::read_u16(&packet[0..2]),
            SEARCH_REQUEST_LEN as u16
        );
        assert_eq!(LittleEndian::read_u32(&packet[4..8]), IXFF);
        assert_eq!(LittleEndian::read_u16(&packet[0x08..0x0a]), 0x13);
        assert_eq!(packet[0x0a], 0x80);
        assert_eq!(packet[0x0b], TCP_SEARCH_ALL);
        assert_eq!(packet[0x10], 0x02);
        assert_eq!(LittleEndian::read_u32(&packet[0x14..0x18]), 60_000);
        assert_eq!(LittleEndian::read_u32(&packet[0x1c..0x20]), 3);
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
    fn parses_horizon_msb_bitpacked_search_player() {
        let record =
            decode_hex("2202c1c3930ed09ec246f1912c94a300a3100420a2045c00000001600002008b800100");
        let mut packet = vec![0u8; 24 + record.len() + HASH_LEN + KEY_TRAILER_LEN];
        packet[0x0a] = 0x80;
        packet[0x0b] = 0x80;
        LittleEndian::write_u16(&mut packet[0x08..0x0a], (24 + record.len()) as u16);
        packet[24..24 + record.len()].copy_from_slice(&record);

        let response = parse_search_list_packet(&packet).unwrap();
        assert!(response.final_packet);
        assert_eq!(response.players.len(), 1);
        assert_eq!(response.players[0].name, "Aadam");
        assert_eq!(response.players[0].zone, Some(246));
        assert_eq!(response.players[0].nation, Some(1));
        assert_eq!(response.players[0].main_job, Some(15));
        assert_eq!(response.players[0].sub_job, Some(3));
        assert_eq!(response.players[0].main_level, Some(75));
        assert_eq!(response.players[0].sub_level, Some(37));
        assert_eq!(response.players[0].race, Some(1));
        assert_eq!(response.players[0].rank, Some(10));
        assert_eq!(response.players[0].flags1, Some(0x2008));
        assert_eq!(response.players[0].id, Some(165905));
        assert_eq!(response.players[0].flags2, Some(0x2008));
        assert_eq!(response.players[0].languages, Some(0x0002));
    }

    #[test]
    fn encrypted_sea_all_request_validates_as_client_request() {
        let mut writer = SearchCrypto::new();
        let encrypted = writer.encrypt(build_sea_all_request()).unwrap();

        let mut reader = SearchCrypto::new();
        let decrypted = reader.decrypt_client_request_for_test(encrypted).unwrap();

        assert_eq!(decrypted[0x0b], TCP_SEARCH_ALL);
        assert_eq!(decrypted[0x10], 0x02);
        assert_eq!(LittleEndian::read_u16(&decrypted[0x08..0x0a]), 0x13);
    }

    #[test]
    fn encrypted_search_response_validates_after_local_decrypt() {
        let mut packet = vec![0u8; 0x30];
        packet[0x0a] = 0x80;
        packet[0x0b] = 0x80;
        LittleEndian::write_u16(&mut packet[0x08..0x0a], 0x18);

        let mut server = SearchCrypto::new();
        let encrypted = server.encrypt_server_response_for_test(packet).unwrap();

        let mut client = SearchCrypto::new();
        let decrypted = client.decrypt(encrypted).unwrap();

        assert_eq!(decrypted[0x0a], 0x80);
        assert_eq!(decrypted[0x0b], 0x80);
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                ((hi << 4) | lo) as u8
            })
            .collect()
    }
}
