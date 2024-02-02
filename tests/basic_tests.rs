use decree::decree::Decree;

// Decree::new tests
#[test]
fn test_invalid_labels()
{
    let invalid_labels: [&'static str; 0] = [];
    let challenges: [&'static str; 1] = ["challenge1"];
    match Decree::new("test", &invalid_labels, &challenges) {
        Ok(_) => { panic!("test_invalid_labels failure"); },
        Err(e) => { assert_eq!(e, "Must specify at least one input"); },
    }
}

#[test]
fn test_invalid_challenges()
{
    let invalid_challenges: [&'static str; 0] = [];
    let labels: [&'static str; 1] = ["input1"];
    match Decree::new("test", &labels, &invalid_challenges) {
        Ok(_) => { panic!("test_invalid_challenges failure"); },
        Err(e) => { assert_eq!(e, "Must specify at least one challenge"); },
    }
}


// Decree::add_input tests
#[test]
fn test_add_invalid_label()
{
    let labels = ["input1"];
    let challenges = ["challenge"];
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_invalid_label failed to create Decree"); }
    };

    match my_decree.add_bytes("invalid_label", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_invalid_label failure"); },
        Err(e) => { assert_eq!(e, "Invalid label"); },
    }
}

#[test]
fn test_add_label_twice()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let labels = ["input1", "input2"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_invalid_label failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Err(_) => { panic!("test_add_label_twice failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_label_twice failure"); },
        Err(e) => { assert_eq!(e, "Label already used"); },
    }
}

#[test]
fn test_add_post_commit()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let labels = ["input1", "input2"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_post_commit failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Err(_) => { panic!("test_add_post_commit failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input2", &buf.to_vec()) {
        Err(_) => { panic!("test_add_post_commit failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input2", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_post_commit failure"); },
        Err(e) => { assert_eq!(e, "Cannot add values after commitment"); }
    }
}

// Decree::get_challenge tests
#[test]
fn test_challenge_unspec()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let labels = ["input1"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_unspec failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenge_unspec failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];
    match my_decree.get_challenge("invalid_challenge", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_unspec failure"); }
        Err(e) => { assert_eq!(e, "Requested challenge not in spec"); }
    }
}

#[test]
fn test_challenge_order()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let labels = ["input1"];
    let challenges = ["challenge1", "challenge2"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_order failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenge_order failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];
    match my_decree.get_challenge("challenge2", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_order failure"); }
        Err(e) => { assert_eq!(e, "Challenge order incorrect"); }
    }
}

#[test]
fn test_challenges_empty()
{
    let labels = ["input1"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenges_empty failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenges_empty failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];

    match my_decree.get_challenge("challenge1", &mut out_buffer) {
        Err(_) => { panic!("test_challenges_empty failure"); }
        Ok(_) => { },
    }

    match my_decree.get_challenge("challenge2", &mut out_buffer) {
        Ok(_) => { panic!("test_challenges_empty failure"); }
        Err(e) => { assert_eq!(e, "No remaining challenges"); },
    }
}

#[test]
fn test_challenge_not_ready()
{
    let labels = ["input1", "input2"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_not_ready failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenges_empty failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];

    match my_decree.get_challenge("challenge1", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_not_ready failure"); },
        Err(e) => { assert_eq!(e, "Missing transcript parameters"); }
    }
}

// Decree::extend tests
#[test]
fn test_extend_not_all_labels() {
    let labels = ["input1", "input2"];
    let challenges = ["challenge1"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_extend_not_all_labels failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_extend_not_all_labels failure"); },
    }

    match my_decree.extend(&labels, &challenges) {
        Ok(_) => { panic!("test_extend_not_all_labels failure"); },
        Err(e) => { assert_eq!(e, "Cannot extend Decree until all challenges generated"); }
    }
}

#[test]
fn test_extend_not_all_challenges() {
    let labels = ["input1"];
    let challenges = ["challenge1", "challenge2"];
    let mut my_decree = match Decree::new("test", &labels, &challenges) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_extend_not_all_challenges failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_extend_not_all_challenges failure"); },
    }

    let mut out_buf: [u8; 32] = [0; 32];
    match my_decree.get_challenge("challenge1", &mut out_buf) {
        Err(_) => { panic!("test_extend_not_all_challenges failure"); }
        Ok(_) => { },
    }

    match my_decree.extend(&labels, &challenges) {
        Ok(_) => { panic!("test_extend_not_all_labels failure"); },
        Err(e) => { assert_eq!(e, "Cannot extend Decree until all challenges generated"); }
    }
}