pub fn bundled_hands() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // ... existing hands ...
        ("zero-guardrails", include_str!("hands/zero_guardrails/HAND.toml"), ""),
    ]
}
