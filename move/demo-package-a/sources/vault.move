#[allow(lint(public_entry))]
module demo_package_a::vault {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct Treasury has key, store {
        id: UID,
        admin: address,
        sweep_count: u64,
    }

    public entry fun init_treasury(ctx: &mut TxContext) {
        transfer::share_object(Treasury {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            sweep_count: 0,
        });
    }

    public entry fun admin_sweep(treasury: &mut Treasury, recipient: address) {
        treasury.admin = recipient;
        treasury.sweep_count = treasury.sweep_count + 1;
    }

    public entry fun withdraw_all(treasury: &mut Treasury) {
        treasury.sweep_count = treasury.sweep_count + 1;
    }
}
