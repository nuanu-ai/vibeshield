import type { RemediationAction } from "../domain/action.js";
import type {
  ModelEnhanceBatchInput,
  ModelHypothesisEnrichBatchInput,
  ModelHypothesisEnrichment,
  ModelProvider,
} from "../ports/model-provider.js";

/** Deliberately unavailable model adapter so deterministic catalog text is used. */
export class NullModelProvider implements ModelProvider {
  async isAvailable(): Promise<boolean> {
    return false;
  }

  async enhance(_input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    return null;
  }

  async enrichHypotheses(
    _input: ModelHypothesisEnrichBatchInput,
  ): Promise<ReadonlyArray<ModelHypothesisEnrichment> | null> {
    return null;
  }
}
