# Third-Party Notices

K2F PURGE includes or adapts the following third-party code and data. The
notices below apply to those portions only.

## magpie (int8 BERT / ONNX / tokenizer port)

- Project: `yetone/magpie` — https://github.com/yetone/magpie
- Revision referenced: `1a67ca614ed6a8180eaf6ea0442dd1272e43d603`
- License: MIT
- Used for: the int8 BERT forward pass, minimal ONNX initializer parser, and
  XLM-R Unigram tokenizer adapted into `internal/astrlink`.
- Copyright (c) 2026 yetone

```
MIT License

Copyright (c) 2026 yetone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## AstrLink Guard model files

- Model: `QuantumNous/astrlink-guard` — https://huggingface.co/QuantumNous/astrlink-guard
- Revision: `7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4`
- License: Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0
- Redistributed files (unmodified, fetched by `scripts/fetch-astrlink.*`):
  - `int8/model_int8.onnx` — 330,781 bytes
    — `0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a`
  - `int8/model_int8.onnx_data` — 37,124,608 bytes
    — `0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067`
  - `int8/tokenizer.json` — 1,502,881 bytes
    — `0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4`

The model files are not covered by the K2F PURGE license. Copyright and any
NOTICE content remain as published upstream. The files are bundled with
release builds and are never downloaded at application runtime; the fetch
scripts run only during packaging.
