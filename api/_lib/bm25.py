"""Minimal BM25 (Okapi) over the precomputed tokenized corpus."""

from __future__ import annotations

import math
from collections import Counter

K1 = 1.2
B = 0.75


class BM25:
    def __init__(self, corpus: dict[str, list[str]]):
        self.docs = dict(corpus)
        self.n = len(self.docs)
        self.avgdl = (sum(len(d) for d in self.docs.values()) / self.n) if self.n else 0.0
        self.doc_tf = {k: Counter(v) for k, v in self.docs.items()}
        self.df: Counter[str] = Counter()
        for tf in self.doc_tf.values():
            for term in tf:
                self.df[term] += 1

    def _idf(self, term: str) -> float:
        df = self.df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log((self.n - df + 0.5) / (df + 0.5) + 1.0)

    def search(self, query_terms: list[str], limit: int = 10,
               offset: int = 0) -> list[tuple[str, float]]:
        scores: dict[str, float] = {}
        for key, tf in self.doc_tf.items():
            dl = len(self.docs[key]) or 1
            score = 0.0
            for term in query_terms:
                f = tf.get(term, 0)
                if not f:
                    continue
                score += self._idf(term) * (f * (K1 + 1)) / (
                    f + K1 * (1 - B + B * dl / self.avgdl))
            if score > 0:
                scores[key] = score
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[offset:offset + limit]
