import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { err } from '../helpers/format.js';

const router = Router();

const aiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many AI requests. Please wait before trying again.' },
});

const summaryCache = new Map();
const SUMMARY_CACHE_TTL = 2 * 60 * 1000;

// POST /pma/ai/summarise
router.post('/summarise', aiLimiter, async (req, res) => {
  const apiKey = process.env.HUGGINGFACE_API_KEY;
  if (!apiKey) return res.status(500).json(err('HUGGINGFACE_API_KEY is not set on the server.'));
  const { inputs } = req.body;
  if (!inputs || typeof inputs !== 'string') return res.status(400).json(err('Missing or invalid "inputs" field.'));

  const cacheKey = inputs.trim();
  const cached = summaryCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return res.json(cached.data);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);

  try {
    const hfRes = await fetch('https://router.huggingface.co/hf-inference/models/facebook/bart-large-cnn', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ inputs, parameters: { max_length: 120, min_length: 20, do_sample: false } }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const rawText = await hfRes.text();
    let data;
    try { data = JSON.parse(rawText); } catch { data = { error: rawText }; }
    if (!hfRes.ok) {
      if (hfRes.status === 503) return res.status(503).json(err('The AI model is warming up, please try again in a few seconds.'));
      return res.status(hfRes.status).json(err(data?.error ?? `HF API error ${hfRes.status}`));
    }
    summaryCache.set(cacheKey, { data, expiresAt: Date.now() + SUMMARY_CACHE_TTL });
    setTimeout(() => summaryCache.delete(cacheKey), SUMMARY_CACHE_TTL);
    res.json(data);
  } catch (e) {
    clearTimeout(timeout);
    if (e.name === 'AbortError') return res.status(504).json(err('AI request timed out. Please try again.'));
    console.error('[AI] HF proxy error:', e.message);
    res.status(502).json(err('AI service temporarily unavailable'));
  }
});

export default router;
