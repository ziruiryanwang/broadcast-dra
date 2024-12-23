use broadcast_dra::audit::emit_provenance;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    emit_provenance()
}
