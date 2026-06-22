import type { StageId } from "../domain/run.js";
import type { StageDefinition } from "./stage-definition.js";

export class StageRegistry {
  private readonly stages = new Map<StageId, StageDefinition>();

  register(stage: StageDefinition): void {
    if (this.stages.has(stage.id)) {
      throw new Error(`Duplicate stage id: ${stage.id}`);
    }
    this.stages.set(stage.id, stage);
  }

  get(stageId: StageId): StageDefinition | undefined {
    return this.stages.get(stageId);
  }

  ordered(): StageDefinition[] {
    const out: StageDefinition[] = [];
    const temporary = new Set<StageId>();
    const permanent = new Set<StageId>();

    const visit = (stageId: StageId): void => {
      if (permanent.has(stageId)) {
        return;
      }
      if (temporary.has(stageId)) {
        throw new Error(`Stage dependency cycle includes ${stageId}`);
      }
      const stage = this.stages.get(stageId);
      if (stage === undefined) {
        throw new Error(`Unknown stage dependency: ${stageId}`);
      }
      temporary.add(stageId);
      for (const dep of stage.dependencies) {
        visit(dep);
      }
      temporary.delete(stageId);
      permanent.add(stageId);
      out.push(stage);
    };

    for (const stageId of this.stages.keys()) {
      visit(stageId);
    }
    return out;
  }
}
