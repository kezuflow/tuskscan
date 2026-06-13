#[allow(lint(public_entry))]
module demo_package_c::lottery {
    use sui::clock::{Self, Clock};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use std::vector;

    public struct Lottery has key, store {
        id: UID,
        players: vector<address>,
        last_winner: address,
        draw_count: u64,
    }

    public entry fun create_lottery(ctx: &mut TxContext) {
        transfer::share_object(Lottery {
            id: object::new(ctx),
            players: vector[],
            last_winner: @0x0,
            draw_count: 0,
        });
    }

    public entry fun join(lottery: &mut Lottery, player: address) {
        vector::push_back(&mut lottery.players, player);
    }

    public entry fun draw_winner(lottery: &mut Lottery, clock: &Clock) {
        let player_count = vector::length(&lottery.players);
        let index = clock::timestamp_ms(clock) % player_count;
        lottery.last_winner = *vector::borrow(&lottery.players, index);
        lottery.draw_count = lottery.draw_count + 1;
    }

    public entry fun eject_player(lottery: &mut Lottery, index: u64) {
        vector::swap_remove(&mut lottery.players, index);
    }
}
