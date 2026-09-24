//! The tiled tree against the reference: a log grown by `append` in uneven batches past
//! the level-1 and level-2 tile boundaries has, at every size, the reference root and the
//! reference proofs, and exactly the tiles tlog-tiles says it must serve.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::collections::HashMap;

use remit_log::tiles::{append, bundle_path, decode_bundle, encode_bundle, tile_path};
use remit_log::{
    Hash, TileError, TileSource, Tiles, consistency_proof, inclusion_proof, leaf_hash, root,
};

#[derive(Default)]
struct Memory(HashMap<String, Vec<Hash>>);

impl TileSource for Memory {
    fn read_tile(&self, level: u8, index: u64, width: u64) -> Result<Vec<Hash>, TileError> {
        let path = tile_path(level, index, width);
        self.0.get(&path).cloned().ok_or(TileError::Missing(path))
    }
}

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect()
}

fn grow(mem: &mut Memory, size: u64, new: &[Hash]) {
    for w in append(mem, size, new).unwrap() {
        if w.hashes.len() == 256 {
            // A full tile, once written, never changes.
            if let Some(old) = mem.0.get(&w.path()) {
                assert_eq!(old, &w.hashes, "{} rewritten", w.path());
            }
        }
        mem.0.insert(w.path(), w.hashes);
    }
}

#[test]
fn paths_follow_tlog_tiles() {
    assert_eq!(tile_path(0, 1_234_067, 256), "tile/0/x001/x234/067");
    assert_eq!(tile_path(0, 0, 256), "tile/0/000");
    assert_eq!(tile_path(3, 999, 7), "tile/3/999.p/7");
    assert_eq!(tile_path(1, 1000, 256), "tile/1/x001/000");
    assert_eq!(bundle_path(5, 12), "tile/entries/005.p/12");
    assert_eq!(bundle_path(1_000_000, 256), "tile/entries/x001/x000/000");
}

#[test]
fn bundles_round_trip_and_refuse_overruns() {
    let entries = vec![vec![], vec![1, 2, 3], vec![9; 300]];
    let bytes = encode_bundle(&entries).unwrap();
    assert_eq!(decode_bundle(&bytes).unwrap(), entries);
    assert!(decode_bundle(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_bundle(&[0]).is_err());
    assert!(encode_bundle(&[vec![0; 65_536]]).is_err());
}

#[test]
fn a_grown_tree_matches_the_reference_at_every_size() {
    let all = leaves(1500);
    let mut mem = Memory::default();
    let mut size = 0usize;
    for batch in [1, 1, 2, 5, 250, 1, 7, 256, 3, 300, 1, 512, 161] {
        grow(&mut mem, size as u64, &all[size..size + batch]);
        size += batch;
        let tiles = Tiles::new(&mem, size as u64);
        assert_eq!(tiles.root().unwrap(), root(&all[..size]), "size {size}");
        for index in [0, 1, size / 3, size / 2, size - 1]
            .into_iter()
            .filter(|&i| i < size)
        {
            assert_eq!(
                tiles.inclusion_proof(index as u64).unwrap(),
                inclusion_proof(&all[..size], index).unwrap(),
                "inclusion {index} of {size}"
            );
        }
        for old in [0, 1, 2, 3, 255, 256, 257, 511, 512, 700, size - 1, size] {
            if old <= size {
                assert_eq!(
                    tiles.consistency_proof(old as u64).unwrap(),
                    consistency_proof(&all[..size], old).unwrap(),
                    "consistency {old} to {size}"
                );
            }
        }
    }
    assert_eq!(size, 1500);
    // An earlier checkpoint's tree can still be read: its partial tiles were kept. A size
    // no checkpoint had has no partial tiles, and is refused rather than guessed.
    let tiles = Tiles::new(&mem, 1339);
    assert_eq!(tiles.root().unwrap(), root(&all[..1339]));
    assert!(matches!(
        Tiles::new(&mem, 1300).root(),
        Err(TileError::Missing(_))
    ));
    assert!(Tiles::new(&mem, 1500).inclusion_proof(1500).is_err());
}

#[test]
fn every_proof_in_a_small_tree_matches_the_reference() {
    let all = leaves(600);
    let mut mem = Memory::default();
    grow(&mut mem, 0, &all);
    let tiles = Tiles::new(&mem, 600);
    for i in 0..600 {
        assert_eq!(
            tiles.inclusion_proof(i as u64).unwrap(),
            inclusion_proof(&all, i).unwrap()
        );
    }
    for old in 0..=600 {
        assert_eq!(
            tiles.consistency_proof(old as u64).unwrap(),
            consistency_proof(&all, old).unwrap()
        );
    }
}

#[test]
fn the_tlog_tiles_example_of_70000_entries() {
    // "A tree of size 70,000 will be represented by 273 full level 0 tiles, one partial
    // level 0 tile of width 112, one full level 1 tile, one partial level 1 tile of width
    // 17, and one partial level 2 tile of width 1."
    let all = leaves(70_000);
    let mut mem = Memory::default();
    let mut size = 0;
    for chunk in all.chunks(9_999) {
        grow(&mut mem, size as u64, chunk);
        size += chunk.len();
    }
    let full0 = (0..273).all(|i| mem.0.contains_key(&tile_path(0, i, 256)));
    assert!(full0);
    assert!(mem.0.contains_key(&tile_path(0, 273, 112)));
    assert!(mem.0.contains_key(&tile_path(1, 0, 256)));
    assert!(mem.0.contains_key(&tile_path(1, 1, 17)));
    assert!(mem.0.contains_key(&tile_path(2, 0, 1)));
    assert!(!mem.0.contains_key(&tile_path(0, 274, 256)));
    let tiles = Tiles::new(&mem, 70_000);
    assert_eq!(tiles.root().unwrap(), root(&all));
    for index in [0, 65_535, 65_536, 69_999] {
        assert_eq!(
            tiles.inclusion_proof(index).unwrap(),
            inclusion_proof(&all, index as usize).unwrap()
        );
    }
    for old in [1, 65_536, 65_537, 69_999] {
        assert_eq!(
            tiles.consistency_proof(old).unwrap(),
            consistency_proof(&all, old as usize).unwrap()
        );
    }
}

#[test]
fn a_missing_or_short_tile_is_an_error_not_a_guess() {
    let all = leaves(300);
    let mut mem = Memory::default();
    grow(&mut mem, 0, &all);
    mem.0.remove(&tile_path(0, 1, 44));
    assert!(matches!(
        Tiles::new(&mem, 300).root(),
        Err(TileError::Missing(_))
    ));
    mem.0.insert(tile_path(0, 1, 44), vec![[0; 32]; 3]);
    assert!(matches!(
        Tiles::new(&mem, 300).root(),
        Err(TileError::Corrupt(_))
    ));
}
