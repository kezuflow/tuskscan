module tuskscan::audit {
    use sui::clock::{Self, Clock};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::object::{Self, UID};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::option::{Self, Option};

    const E_INSUFFICIENT_PAYMENT: u64 = 0;
    const E_JOB_ALREADY_FINALIZED: u64 = 1;
    const E_INVALID_OPERATOR: u64 = 2;

    const INITIAL_PRICE_MIST: u64 = 1000000;

    const STATUS_PAID: u8 = 1;
    const STATUS_COMPLETED: u8 = 3;

    public struct OperatorCap has key, store {
        id: UID,
    }

    public struct AuditConfig has key, store {
        id: UID,
        price_mist: u64,
        operator: address,
    }

    public struct AuditJob has key, store {
        id: UID,
        payer: address,
        package_id: vector<u8>,
        package_digest: vector<u8>,
        price_paid: u64,
        status: u8,
        created_at_ms: u64,
        report_id: Option<address>,
    }

    public struct AuditReport has key, store {
        id: UID,
        job_id: address,
        package_id: vector<u8>,
        package_snapshot_blob_id: vector<u8>,
        package_snapshot_hash: vector<u8>,
        report_blob_id: vector<u8>,
        report_hash: vector<u8>,
        findings_hash: vector<u8>,
        risk_score: u64,
        visibility: u8,
        created_at_ms: u64,
    }

    public struct AuditJobCreated has copy, drop {
        job_id: address,
        payer: address,
        package_id: vector<u8>,
        price_paid: u64,
    }

    public struct AuditReportFinalized has copy, drop {
        report_id: address,
        job_id: address,
        risk_score: u64,
        visibility: u8,
    }

    fun init(ctx: &mut TxContext) {
        let operator = tx_context::sender(ctx);
        transfer::transfer(
            OperatorCap { id: object::new(ctx) },
            operator,
        );
        transfer::share_object(AuditConfig {
            id: object::new(ctx),
            price_mist: INITIAL_PRICE_MIST,
            operator,
        });
    }

    entry fun create_audit_job(
        config: &AuditConfig,
        package_id: vector<u8>,
        package_digest: vector<u8>,
        payment: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let price_paid = coin::value(&payment);
        assert!(price_paid >= config.price_mist, E_INSUFFICIENT_PAYMENT);

        let job = AuditJob {
            id: object::new(ctx),
            payer: tx_context::sender(ctx),
            package_id,
            package_digest,
            price_paid,
            status: STATUS_PAID,
            created_at_ms: clock::timestamp_ms(clock),
            report_id: option::none(),
        };
        let job_id = object::uid_to_address(&job.id);
        event::emit(AuditJobCreated {
            job_id,
            payer: tx_context::sender(ctx),
            package_id: job.package_id,
            price_paid,
        });
        transfer::public_transfer(payment, config.operator);
        transfer::share_object(job);
    }

    entry fun set_price(_: &OperatorCap, config: &mut AuditConfig, price_mist: u64) {
        config.price_mist = price_mist;
    }

    entry fun set_operator(_: &OperatorCap, config: &mut AuditConfig, operator: address) {
        assert!(operator != @0x0, E_INVALID_OPERATOR);
        config.operator = operator;
    }

    entry fun finalize_report(
        _: &OperatorCap,
        job: &mut AuditJob,
        package_snapshot_blob_id: vector<u8>,
        package_snapshot_hash: vector<u8>,
        report_blob_id: vector<u8>,
        report_hash: vector<u8>,
        findings_hash: vector<u8>,
        risk_score: u64,
        visibility: u8,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(job.status == STATUS_PAID, E_JOB_ALREADY_FINALIZED);
        let job_id = object::uid_to_address(&job.id);

        let report = AuditReport {
            id: object::new(ctx),
            job_id,
            package_id: job.package_id,
            package_snapshot_blob_id,
            package_snapshot_hash,
            report_blob_id,
            report_hash,
            findings_hash,
            risk_score,
            visibility,
            created_at_ms: clock::timestamp_ms(clock),
        };
        let report_id = object::uid_to_address(&report.id);
        job.status = STATUS_COMPLETED;
        job.report_id = option::some(report_id);

        event::emit(AuditReportFinalized { report_id, job_id, risk_score, visibility });
        transfer::transfer(report, job.payer);
    }

    public fun job_status(job: &AuditJob): u8 {
        job.status
    }

    public fun job_report_id(job: &AuditJob): Option<address> {
        job.report_id
    }
}
