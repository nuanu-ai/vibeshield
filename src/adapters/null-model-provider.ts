import type { RemediationAction } from "../domain/action.js";
import type { ModelEnhanceBatchInput, ModelProvider } from "../ports/model-provider.js";

/** Current Quick Scan model adapter: deliberately unavailable so catalog remediation is used. */
export class NullModelProvider implements ModelProvider {
  async isAvailable(): Promise<boolean> {
    return false;
  }

  async enhance(_input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    return null;
  }
}
