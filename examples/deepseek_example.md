# DeepSeek V3 Integration Example

This document shows how to use DeepSeek V3 as the primary LLM provider with Hound.

## Setup

1. **Get a DeepSeek API key** from [https://platform.deepseek.com](https://platform.deepseek.com)

2. **Set environment variables:**

```bash
export DEEPSEEK_API_KEY="your-api-key-here"
# Optional: use a custom base URL
export DEEPSEEK_BASE_URL="https://api.deepseek.com"
```

3. **Configure models** in `config.yaml`:

```yaml
deepseek:
  api_key_env: DEEPSEEK_API_KEY
  base_url: https://api.deepseek.com

models:
  # Scout/agent model for exploration
  scout:
    provider: deepseek
    model: deepseek-chat
    max_context: 256000
  
  # Strategic thinking model
  strategist:
    provider: deepseek
    model: deepseek-chat
    max_context: 256000
```

## Running an Audit with DeepSeek

```bash
# Create a project
./hound.py project create myaudit /path/to/code

# Build knowledge graphs
./hound.py graph build myaudit --auto --files "src/main.sol,src/lib.sol"

# Run security audit with DeepSeek
./hound.py agent audit myaudit --mode sweep

# For deeper analysis
./hound.py agent audit myaudit --mode intuition --time-limit 60
```

## Cost Savings

DeepSeek V3 offers significant cost savings compared to GPT-4:

- **DeepSeek Chat**: ~$0.14 per 1M input tokens, ~$0.28 per 1M output tokens
- **GPT-4**: ~$5.00 per 1M input tokens, ~$15.00 per 1M output tokens

This represents approximately **90% cost reduction** for typical audit workloads.

## Prompt Compatibility

The DeepSeek provider in Hound includes automatic fallback handling:

1. **Structured Output Mode**: First attempts OpenAI-compatible structured output API
2. **JSON Mode Fallback**: If structured output fails, falls back to JSON mode with schema instructions
3. **System Role Support**: DeepSeek fully supports system/user message roles

This ensures compatibility with all of Hound's prompt patterns without modification.

## Verification

To verify your DeepSeek integration is working:

```bash
# Run with debug mode to see API calls
./hound.py agent audit myaudit --debug --mode sweep --time-limit 5

# Check the logs in .hound_debug/ for DeepSeek API interactions
```

## Mixed Provider Setup

You can also use DeepSeek for some models and other providers for others:

```yaml
models:
  scout:
    provider: deepseek
    model: deepseek-chat
  
  strategist:
    provider: openai
    model: gpt-4o
  
  graph:
    provider: gemini
    model: gemini-2.5-pro
```

This allows you to optimize for both cost and capability based on the task.
