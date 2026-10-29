"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

export function useApi<T>(loader: () => Promise<T>, deps: readonly unknown[] = []): ApiState<T> {
  const loaderRef = useRef(loader);
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  loaderRef.current = loader;

  const reload = useCallback(() => setRevision((current) => current + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    loaderRef.current()
      .then((result) => { if (!controller.signal.aborted) setData(result); })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Unable to load data");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // The loader is intentionally kept in a ref; callers control refetches via deps/reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, revision]);

  return { data, loading, error, reload };
}
