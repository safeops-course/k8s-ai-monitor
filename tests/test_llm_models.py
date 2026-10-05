"""Default models, pricing by longest prefix, and the OpenAI token parameter."""
import unittest
from unittest import mock

from src import config
from src.engine import llm


class TestDefaultModels(unittest.TestCase):
    def test_defaults_per_provider_and_tier(self):
        cases = {("gemini", "alert"): "gemini-3.5-flash-lite", ("gemini", "report"): "gemini-3.8-flash",
                 ("openai", "alert"): "gpt-6-luna", ("openai", "report"): "gpt-6.1-sol",
                 ("anthropic", "alert"): "claude-haiku-4-5-20251001",
                 ("anthropic", "report"): "claude-sonnet-5-5"}
        with mock.patch.object(config, "LLM_MODEL", ""), mock.patch.object(config, "LLM_MODEL_REPORT", ""):
            for (provider, tier), model in cases.items():
                self.assertEqual(llm._get_model(provider, tier), model, (provider, tier))

    def test_every_default_has_a_price(self):
        with mock.patch.object(config, "LLM_MODEL", ""), mock.patch.object(config, "LLM_MODEL_REPORT", ""):
            for provider in ("gemini", "openai", "anthropic"):
                for tier in ("alert", "report"):
                    model = llm._get_model(provider, tier)
                    self.assertIsNotNone(llm._estimate_cost(model, 1000, 1000), model)


class TestPricing(unittest.TestCase):
    def test_longest_prefix_wins(self):
        # 1M in + 1M out: flash-lite 0.30 + 2.50, never flash 1.50 + 9.00
        self.assertAlmostEqual(llm._estimate_cost("gemini-3.5-flash-lite", 1_000_000, 1_000_000), 2.80)
        self.assertAlmostEqual(llm._estimate_cost("gemini-3.5-flash", 1_000_000, 1_000_000), 10.50)

    def test_unknown_model_has_no_price(self):
        self.assertIsNone(llm._estimate_cost("some-new-model", 10, 10))


class TestOpenAITokenParam(unittest.TestCase):
    def test_new_models_use_max_completion_tokens(self):
        for model in ("gpt-5-mini", "gpt-6-luna", "gpt-6.1-sol"):
            self.assertEqual(llm._openai_token_param(model), "max_completion_tokens", model)
        for model in ("gpt-4o-mini", "gpt-4.1-nano"):
            self.assertEqual(llm._openai_token_param(model), "max_tokens", model)


if __name__ == "__main__":
    unittest.main()
