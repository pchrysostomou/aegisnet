/**
 * The shape a form action reports back, kept out of the `"use server"` module.
 *
 * Next refuses any non-function export from a file marked `"use server"`: every export there
 * becomes a callable server endpoint, so a constant would be a nonsense one. The type is
 * erased at build time and would have been fine, but the initial value is not — and the error
 * only appears when the action actually runs, which is why the browser test caught what
 * `tsc`, ESLint, the unit tests and `next build` all let through.
 */
export interface ActionState {
  error: string | null;
  ok: boolean;
}

export const idle: ActionState = { error: null, ok: false };
