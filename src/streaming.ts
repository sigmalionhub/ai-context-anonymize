import type { AnonymizerConfig, ProtectResult } from "./types.ts";
import { buildRules, collectMatches, applyMatches, type ApplyState } from "./engine.ts";

/** Return value of `StreamingAnonymizer#write()`. */
export interface StreamWriteResult {
  /** Anonymized text safe to forward downstream. `""` when `isSafe` is `false` or the buffer is still filling. */
  output: string;
  /** `false` when a BLOCK rule fired; stop the stream immediately. */
  isSafe: boolean;
  /** Names of BLOCK rules that fired. Empty when `isSafe` is `true`. */
  violations: string[];
}

/**
 * Token-by-token anonymizer for LLM streaming output.
 *
 * Feed chunks as they arrive with `write()`; call `flush()` when the stream
 * ends to process any buffered remainder. The `windowSize` tail is held back
 * on each `write()` to ensure PII that spans chunk boundaries is caught.
 *
 * @example
 * const stream = new StreamingAnonymizer({ windowSize: 512 });
 * for (const chunk of llmStream) {
 *   const { output, isSafe } = stream.write(chunk);
 *   if (!isSafe) { closeStream(); break; }
 *   forward(output);
 * }
 * const final = stream.flush();
 * if (final.isSafe) forward(final.protectedText);
 * const answer = restore(fullResponse, final.map);
 */
export class StreamingAnonymizer {
  private readonly rules: ReturnType<typeof buildRules>;
  private readonly redactPlaceholder: string;
  private readonly windowSize: number;
  private readonly maxBufferSize: number;
  private buffer: string = "";
  private readonly state: ApplyState;
  private aborted: boolean = false;
  private abortViolations: string[] = [];
  private flushed: boolean = false;

  constructor(config: AnonymizerConfig = {}) {
    this.rules = buildRules(config);
    this.redactPlaceholder = config.redactPlaceholder ?? "«REDACTED»";
    this.windowSize = config.windowSize ?? 2048;
    this.maxBufferSize = config.maxBufferSize ?? 0;
    const nonceProvider = config.nonceProvider ?? (() => Math.random().toString(36).slice(2, 7));
    this.state = {
      valueToToken: new Map(),
      tokenToValue: new Map(),
      counters: new Map(),
      nonce: nonceProvider(),
    };
  }

  /**
   * Append a chunk to the internal buffer and emit the portion that is
   * safely past the `windowSize` overlap guard.
   *
   * @returns `output` — anonymized text ready to forward; `""` while the
   *   buffer is still filling or after an abort.
   */
  write(chunk: string): StreamWriteResult {
    if (this.aborted) return { output: "", isSafe: false, violations: this.abortViolations };
    if (this.flushed) return { output: "", isSafe: true, violations: [] };

    this.buffer += chunk.normalize("NFC");

    if (this.maxBufferSize > 0 && this.buffer.length > this.maxBufferSize) {
      throw new Error(`ai-context-anonymize: buffer exceeded maxBufferSize (${this.maxBufferSize})`);
    }

    const safeBoundary = Math.max(0, this.buffer.length - this.windowSize);
    if (safeBoundary === 0) return { output: "", isSafe: true, violations: [] };

    const safeText = this.buffer.slice(0, safeBoundary);
    const { output, violations } = applyMatches(
      safeText,
      collectMatches(safeText, this.rules),
      this.state,
      this.redactPlaceholder,
    );

    if (violations.length > 0) {
      this.aborted = true;
      this.abortViolations = violations;
      return { output: "", isSafe: false, violations };
    }

    this.buffer = this.buffer.slice(safeBoundary);
    return { output, isSafe: true, violations: [] };
  }

  /**
   * Process the remaining buffer and finalize the session.
   *
   * Safe to call multiple times — subsequent calls return the same result
   * without reprocessing. Use `flush().map` as the restore map for the full
   * concatenated LLM response.
   */
  flush(): ProtectResult {
    if (this.aborted) {
      return { protectedText: "", map: new Map(), isSafe: false, violations: this.abortViolations };
    }
    if (this.flushed) {
      return { protectedText: "", map: new Map(this.state.tokenToValue), isSafe: true, violations: [] };
    }

    this.flushed = true;
    const { output, violations } = applyMatches(
      this.buffer,
      collectMatches(this.buffer, this.rules),
      this.state,
      this.redactPlaceholder,
    );
    this.buffer = "";

    if (violations.length > 0) {
      this.aborted = true;
      this.abortViolations = violations;
      return { protectedText: "", map: new Map(), isSafe: false, violations };
    }

    return { protectedText: output, map: new Map(this.state.tokenToValue), isSafe: true, violations: [] };
  }
}
