use broadcast_dra::{
    FalseBid, PublicBroadcastDRA, Uniform, ValueDistribution,
};

fn main() {
    let dist = Uniform::new(0.0, 20.0);
    let alpha = dist.strong_regular_alpha().unwrap_or(1.0);
    let dra = PublicBroadcastDRA::new(dist.clone(), alpha);

    let valuations = vec![15.0, 11.0, 8.0];
    let false_bids = vec![FalseBid {
        bid: 30.0,
        reveal: false,
    }];

    let outcome = dra.run_with_false_bids(&valuations, &false_bids, None);

    println!("=== DRA with public broadcast ===");
    println!("distribution reserve: {:.3}", dist.reserve_price());
    println!("collateral requirement: {:.3}", outcome.collateral);
    println!("valid bids: {:?}", outcome.valid_bids);
    match &outcome.winner {
        Some(w) => {
            println!("winner: {:?}, bid {:.3}, payment {:.3}", w, outcome.winning_bid, outcome.payment);
            println!("collateral transferred to winner: {:.3}", outcome.transferred_collateral);
        }
        None => {
            println!("no allocation; forfeited collateral retained by auctioneer: {:.3}", outcome.forfeited_to_auctioneer);
        }
    }
}
