#[allow(lint(public_entry))]
module demo_package_b::reserve {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct Reserve has key, store {
        id: UID,
        owner: address,
        claim_count: u64,
    }

    public entry fun init_reserve(ctx: &mut TxContext) {
        transfer::share_object(Reserve {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            claim_count: 0,
        });
    }

    public entry fun owner_config(reserve: &mut Reserve, next_owner: address) {
        reserve.owner = next_owner;
    }

    public entry fun claim_treasury(reserve: &mut Reserve) {
        reserve.claim_count = reserve.claim_count + 1;
    }
}
