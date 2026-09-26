from attacks.attacks import adversarial_prompts


def test_required_red_attack_prompts_are_concrete_and_unique():
    assert len(adversarial_prompts) >= 5
    prompts = [item["input"] for item in adversarial_prompts[:5]]
    assert len(set(prompts)) == 5
    assert all("TODO" not in prompt for prompt in prompts)
    assert all(len(prompt) >= 120 for prompt in prompts)
