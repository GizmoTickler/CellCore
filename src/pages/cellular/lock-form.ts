import { create } from "zustand";

/**
 * Cell-lock form fields. Kept outside the page component because the shell remounts
 * the page on every sub-view change, and "Use this cell" on the Scan view has to
 * hand its values over to the Lock view.
 */
interface LockFormState {
  nrPci: string;
  nrArfcn: string;
  nrScs: string;
  nrBand: string;
  ltePci: string;
  lteEarfcn: string;
  set: (patch: Partial<Omit<LockFormState, "set">>) => void;
}

export const useLockForm = create<LockFormState>((set) => ({
  nrPci: "",
  nrArfcn: "",
  nrScs: "30",
  nrBand: "",
  ltePci: "",
  lteEarfcn: "",
  set: (patch) => set(patch),
}));
