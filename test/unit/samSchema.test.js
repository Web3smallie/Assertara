const assert = require('assert');
const {
  buildSamRequestBody,
  accumulateSegmentationText,
  extractBoxesFromSegmentationText
} = require('../../src/services/samService');

function runSamSchemaTests() {
  console.log('Testing SAM 3.1 Request Schema & Output Parsing...\n');

  // Test 1: Request body matches Meta's documented Responses API shape.
  // See https://dev.meta.ai/docs/sam/segmenting — there is no top-level
  // `prompts` parameter (it 400s with "unknown parameter 'prompts'") and no
  // `image_base64` part type; the image goes in as an `input_image` data URL.
  const body = buildSamRequestBody('sam-3.1', 'button', 'data:image/png;base64,AAA');
  assert.strictEqual(body.model, 'sam-3.1', 'Should target the SAM model');
  assert.ok(!('prompts' in body), 'Body must not contain top-level prompts');
  assert.strictEqual(body.stream, true, 'Should request a streamed response');
  assert.strictEqual(body.input.length, 1, 'Should send one message');
  assert.strictEqual(body.input[0].type, 'message', 'Input item should be a message');
  assert.strictEqual(body.input[0].role, 'user', 'Message role should be user');
  const [textPart, imagePart] = body.input[0].content;
  assert.strictEqual(textPart.type, 'input_text', 'First part should be input_text');
  assert.strictEqual(textPart.text, 'button', 'Should carry the single concept phrase');
  assert.strictEqual(imagePart.type, 'input_image', 'Second part should be input_image');
  assert.strictEqual(imagePart.image_url, 'data:image/png;base64,AAA', 'Should pass the image data URL');
  console.log('✔ Test 1 Passed: Request body uses the documented Meta schema.');

  // Test 2: SSE accumulation concatenates output_text deltas until completion.
  const sse = [
    'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;"}',
    'data: {"type":"response.output_text.delta","delta":"x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}',
    'data: {"type":"response.completed"}',
    ''
  ].join('\n');
  const accumulated = accumulateSegmentationText(sse);
  assert.strictEqual(accumulated.completed, true, 'Should detect response.completed');
  assert.strictEqual(
    accumulated.outputText,
    '<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>',
    'Should concatenate delta payloads in order'
  );
  console.log('✔ Test 2 Passed: Streamed output_text accumulates until completion.');

  // Test 3: Box tokens parse to pixel regions (x2/y2 inclusive per Meta docs).
  const regions = extractBoxesFromSegmentationText(accumulated.outputText, 'button');
  assert.strictEqual(regions.length, 1, 'Should extract one region');
  assert.strictEqual(regions[0].label, 'button', 'Region should keep the concept label');
  assert.deepStrictEqual(
    regions[0].boundingBox,
    { x: 1, y: 2, width: 11, height: 11 },
    'Bounding box should use inclusive x2/y2 pixel math'
  );
  assert.strictEqual(regions[0].confidence, 0.9, 'Should default confidence without include_confidence');
  console.log('✔ Test 3 Passed: Box grammar parses to pixel bounding boxes.');

  // Test 4: Documented image example with confidence parses every record.
  const docLine = '<0f>0<|box;x1=353;y1=382;x2=453;y2=427;w=537;h=561;c=0.96|>'
    + '<|mask;x=0;y=0;c=0.96;data=46,101,~AAA|>,1<|box;x1=260;y1=382;x2=340;y2=427;w=537;h=561|>'
    + '<|mask;x=0;y=0;data=46,81,~BBB|>';
  const docRegions = extractBoxesFromSegmentationText(docLine, 'button');
  assert.strictEqual(docRegions.length, 2, 'Should extract both records');
  assert.strictEqual(docRegions[0].confidence, 0.96, 'Should read confidence by key');
  assert.deepStrictEqual(docRegions[1].boundingBox, { x: 260, y: 382, width: 81, height: 46 });
  console.log('✔ Test 4 Passed: Multi-record output parses with per-record confidence.');

  // Test 5: Zero matches (empty output_text) is valid and yields no regions.
  const empty = accumulateSegmentationText('data: {"type":"response.completed"}\n');
  assert.strictEqual(empty.completed, true, 'Empty stream should still complete');
  assert.strictEqual(empty.outputText, '', 'Zero matches means empty output_text');
  assert.deepStrictEqual(extractBoxesFromSegmentationText(empty.outputText, 'button'), []);
  console.log('✔ Test 5 Passed: Zero-match output is a valid empty result.');

  console.log('\nAll SAM Schema Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runSamSchemaTests();
}

module.exports = { runSamSchemaTests };
