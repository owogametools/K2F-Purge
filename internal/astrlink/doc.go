// Package astrlink runs the AstrLink Guard token classifier locally: an
// int8 BERT ONNX model (QuantumNous/astrlink-guard, Apache-2.0) read by
// onnx.go and run by bert.go on the CPU, with the XLM-R Unigram tokenizer
// in tokenizer.go. Nothing is downloaded and nothing leaves the machine.
//
// The model files are looked up by lookup.go and must match pinned sizes
// and SHA-256 hashes before any inference runs. Scan reads the exposure
// catalog's present files, a bounded slice of each, and reports the
// secrets and personal data the model labels in them.
//
// The ONNX parser, the int8 forward pass and the tokenizer are derived
// from yetone/magpie (MIT), Copyright (c) 2026 yetone.
package astrlink
