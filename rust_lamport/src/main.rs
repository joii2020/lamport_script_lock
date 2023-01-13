use rand::prelude::*;
use rand::thread_rng;

use sha3::{Digest, Sha3_256};

const HASH_SIZE: usize = 256usize;
const HASH_SIZE_BYTE: usize = 32usize; // HASH_SIZE >> 3

// 代码只是用于验证

#[derive(Default, Clone, Copy)]
struct Bytes32 {
    pub inner: [u8; 32],
}

impl Bytes32 {
    pub fn new_rand() -> Self {
        let mut rng = thread_rng();
        let mut r: [u8; HASH_SIZE_BYTE] = [0u8; HASH_SIZE_BYTE];
        rng.fill_bytes(&mut r);
        Self { inner: r }
    }

    pub fn from_vec(d: Vec<u8>) -> Self {
        Self {
            inner: d.try_into().unwrap_or_else(|d: Vec<u8>| {
                panic!("Expected a Vec of length {} but it was {}", 32, d.len())
            }),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn cmp(&self, b: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&b.inner)
    }

    fn get_bits(&self, count: usize) -> u8 {
        let pos = count / 8;
        let offset = count % 8;

        (self.inner[pos] >> offset) & 1
    }
}

static mut HASH_COUNT: usize = 0;
fn sha256(d: &[u8]) -> Bytes32 {
    let mut s = Sha3_256::new();
    s.update(d);
    let r = s.finalize().to_vec();

    unsafe {
        HASH_COUNT += 1;
    }

    Bytes32::from_vec(r)
}

fn get_hash_count() -> usize {
    unsafe {
        let r = HASH_COUNT;
        HASH_COUNT = 0;
        r
    }
}

struct StandardLamport {
    pub pub_key_a: Vec<Bytes32>,
    pub pub_key_b: Vec<Bytes32>,
    pub pri_key_a: Vec<Bytes32>,
    pub pri_key_b: Vec<Bytes32>,
}

impl StandardLamport {
    pub fn new() -> Self {
        let mut pri_key_a = Vec::<Bytes32>::with_capacity(HASH_SIZE);
        let mut pri_key_b = Vec::<Bytes32>::with_capacity(HASH_SIZE);
        let mut pub_key_a = Vec::<Bytes32>::with_capacity(HASH_SIZE);
        let mut pub_key_b = Vec::<Bytes32>::with_capacity(HASH_SIZE);

        for _i in 0..HASH_SIZE {
            let buf = Bytes32::new_rand();
            pri_key_a.push(buf);
            pub_key_a.push(sha256(buf.as_slice()));

            let buf = Bytes32::new_rand();
            pri_key_b.push(buf);
            pub_key_b.push(sha256(buf.as_slice()));
        }

        Self {
            pub_key_a,
            pub_key_b,
            pri_key_a,
            pri_key_b,
        }
    }

    pub fn sign(&self, msg: Bytes32) -> Vec<Bytes32> {
        let mut sign = Vec::<Bytes32>::with_capacity(HASH_SIZE);

        for i in 0..HASH_SIZE {
            let b = msg.get_bits(i);

            if b == 0 {
                sign.push(self.pri_key_a[i]);
            } else {
                sign.push(self.pri_key_b[i]);
            }
        }

        sign
    }

    pub fn verify(&self, msg: Bytes32, sign: &[Bytes32]) -> bool {
        for i in 0..HASH_SIZE {
            let b = msg.get_bits(i);
            let pub_key = if b == 0 {
                self.pub_key_a[i]
            } else {
                self.pub_key_b[i]
            };

            let sign_d = &sign[i];
            let sign_hash = sha256(sign_d.as_slice());
            if sign_hash.cmp(&pub_key).is_ne() {
                return false;
            }
        }
        true
    }
}

fn standard_lamport() {
    let lamport = StandardLamport::new();

    let msg = Bytes32::new_rand();
    println!("standard lamport genkety hash:{}", get_hash_count());

    let sign = lamport.sign(msg);
    println!("standard lamport sign hash:   {}", get_hash_count());

    let ret = lamport.verify(msg, &sign);
    println!("standard lamport verify hash: {}", get_hash_count());

    assert!(ret);
}

// 2^signed_hash_bits + 2
const G_SHORT_LOOP: usize = 258;
const G_SHORT_GROUP: usize = 32;

struct ShortLamport {
    pub pri_key_a: [Bytes32; G_SHORT_GROUP],
    pub pri_key_b: [Bytes32; G_SHORT_GROUP],
    pub pub_key_a: [Bytes32; G_SHORT_GROUP],
    pub pub_key_b: [Bytes32; G_SHORT_GROUP],
}

impl ShortLamport {
    pub fn new() -> Self {
        let mut s = Self {
            pri_key_a: [Bytes32::new_rand(); G_SHORT_GROUP],
            pri_key_b: [Bytes32::new_rand(); G_SHORT_GROUP],
            pub_key_a: [Bytes32::default(); G_SHORT_GROUP],
            pub_key_b: [Bytes32::default(); G_SHORT_GROUP],
        };

        // 这里只是为了方便
        //      其实这步可以放在sign中去做，这样可以节省不少算力
        for i in 0..G_SHORT_GROUP {
            s.pub_key_a[i] = Self::get_loop_hash(&s.pri_key_a[i], G_SHORT_LOOP);
            s.pub_key_b[i] = Self::get_loop_hash(&s.pri_key_b[i], G_SHORT_LOOP);
        }

        s
    }

    fn get_loop_hash(buf: &Bytes32, count: usize) -> Bytes32 {
        let mut buf = buf.clone();
        for _ in 0..count {
            buf = sha256(buf.as_slice());
        }

        buf
    }

    // 在sign的时候去生成public key最合适，否则需要在整个结构体中存储哈希链
    pub fn sign(&self, msg: Bytes32) -> Vec<Bytes32> {
        let mut sign = Vec::new();

        for i in 0..G_SHORT_GROUP {
            let val = msg.inner[i] as usize + 1;

            // A
            let buf = Self::get_loop_hash(&self.pri_key_a[i], val);
            sign.push(buf);

            let buf = Self::get_loop_hash(&self.pri_key_b[i], G_SHORT_LOOP - val);
            sign.push(buf);
        }

        sign
    }

    pub fn verify(&self, msg: Bytes32, sign: &[Bytes32]) -> bool {
        for i in 0..G_SHORT_GROUP {
            let val = msg.inner[i] as usize + 1;

            let sign_all = &sign[(i * 2)..(i + 1) * 2];
            let sign_a = &sign_all[0];

            let buf = Self::get_loop_hash(sign_a, G_SHORT_LOOP - val);
            if buf.cmp(&self.pub_key_a[i]).is_ne() {
                return false;
            }

            let sign_b = &sign_all[1];
            let buf = Self::get_loop_hash(sign_b, val);
            if buf.cmp(&self.pub_key_b[i]).is_ne() {
                return false;
            }
        }
        true
    }
}

fn short_lamport() {
    let lamport = ShortLamport::new();

    let msg = Bytes32::new_rand();
    println!("short lamport genkey hash: {}", get_hash_count());

    let sign = lamport.sign(msg);
    println!("short lamport sign hash:   {}", get_hash_count());

    let ret = lamport.verify(msg, &sign);
    println!("short lamport verify hash: {}", get_hash_count());
    assert!(ret);
}

fn main() {
    standard_lamport();
    short_lamport();
}
