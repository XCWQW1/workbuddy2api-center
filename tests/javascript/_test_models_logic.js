/* 模型页纯逻辑：默认隐藏被排除且未处理的模型、能力筛选、倍率标签、统计与 disabled_models。
 * 运行：node tests/javascript/_test_models_logic.js
 */
import assert from 'node:assert/strict';
import {
  LONG_CONTEXT_TOKENS, accountAvailableCount, accountCanUse, capabilityBadges, contextText,
  coverageFor, creditInfo, creditsValue, disabledIds, fmtTokens, hasCredits, hasReasoning,
  hasVision, hiddenExcludedCount, realmAccounts, reasoningLevels, panelModelsUrl,
  selectModels, sourceLabel, summary, withEnabled,
} from '../../app/web/js/pages/models/logic.js';

const MODELS = [
  { id: 'hy4-preview-f', name: 'Hy4 preview', supports_vision: true, supports_tool_calls: true,
    supports_reasoning: true, always_reasoning: true, reasoning_efforts: ['high'],
    context_length: 1000000, max_output_tokens: 64000, credits: 'x0.00', enabled: true, excluded: false },
  { id: 'glm-5.3', name: 'GLM 5.3', supports_tool_calls: true, supports_reasoning: true,
    reasoning_efforts: ['low', 'high', 'max'], context_length: 1000000, max_output_tokens: 48000,
    credits: 'x0.79', enabled: true, excluded: false },
  { id: 'grok-4.7', name: 'Grok 4.7', supports_reasoning: true,
    reasoning_efforts: ['low', 'medium', 'high', 'xhigh'], context_length: 500000,
    context_windows: [200000, 500000], max_output_tokens: 128000, credits: 1.9, enabled: true, excluded: false },
  { id: 'gemini-3.5-flash', description: 'Fast Gemini', reasoning_fixed_effort: 'medium',
    supports_reasoning: true, context_length: 1000000, max_output_tokens: 65536, enabled: true, excluded: false },
  { id: 'kimi-k2.6', context_length: 256000, max_output_tokens: 32000, credits: 'x0.2',
    enabled: true, excluded: false },
  { id: 'default-model', enabled: false, excluded: true },
  { id: 'deepseek-v4.1-flash-sg', enabled: false, excluded: true, credits: 'x0.03',
    context_length: 128000 },
];

const ids = (rows) => rows.map((m) => m.id);

// 目录来源
assert.equal(sourceLabel('server'), '本次从服务器获取');
assert.equal(sourceLabel('bundled'), '程序内置模型表');
assert.equal(sourceLabel(''), '未知来源');
assert.equal(sourceLabel('something-new'), 'something-new');

// 上下文与输出的显示
assert.equal(fmtTokens(128000), '128K');
assert.equal(fmtTokens(1000000), '1M');
assert.equal(fmtTokens(64000), '64K');
assert.equal(fmtTokens(0), '—');
assert.equal(fmtTokens(null), '—');
assert.equal(contextText({ context_length: 500000 }), '500K');
assert.equal(contextText({ context_windows: [300000, 1000000] }), '300K / 1M');
assert.equal(contextText({}), '—');

// 能力判定使用真实字段
assert.equal(hasVision(MODELS[0]), true);
assert.equal(hasVision({ input_modalities: ['text', 'image'] }), true);
assert.equal(hasVision({ input_modalities: ['text'] }), false);
assert.equal(hasReasoning({ supports_reasoning: true }), true);
assert.equal(hasReasoning({ reasoning_fixed_effort: 'medium' }), true);
assert.equal(hasReasoning({}), false);
assert.deepEqual(reasoningLevels({ reasoning_fixed_effort: 'Medium' }), ['medium']);
assert.deepEqual(reasoningLevels({ reasoning_efforts: ['Low', 'max'] }), ['low', 'max']);
assert.deepEqual(reasoningLevels({ supports_reasoning: true }), ['原生']);
assert.deepEqual(reasoningLevels({}), []);
assert.deepEqual(capabilityBadges({ always_reasoning: true, supports_vision: true }).map((b) => b.key),
                 ['always', 'vision']);
assert.deepEqual(capabilityBadges({ supports_tool_calls: true, is_default: true }).map((b) => b.key),
                 ['tools', 'default']);
assert.deepEqual(capabilityBadges({}).map((b) => b.key), []);

// 被排除且未勾选的模型默认隐藏，展开后显示，勾选后收起仍显示
assert.equal(hiddenExcludedCount(MODELS), 2);
assert.deepEqual(ids(selectModels(MODELS, {})), ['hy4-preview-f', 'glm-5.3', 'grok-4.7', 'gemini-3.5-flash', 'kimi-k2.6']);
assert.deepEqual(ids(selectModels(MODELS, { showExcluded: true })).slice(5).sort(),
                 ['deepseek-v4.1-flash-sg', 'default-model']);
assert.deepEqual(ids(selectModels(withEnabled(MODELS, 'default-model', true), {})),
                 ['hy4-preview-f', 'glm-5.3', 'grok-4.7', 'gemini-3.5-flash', 'kimi-k2.6', 'default-model']);
// 被排除的模型被勾选后不再计入隐藏数量
assert.equal(hiddenExcludedCount(withEnabled(MODELS, 'default-model', true)), 1);

// 搜索命中 id、名称与说明
assert.deepEqual(ids(selectModels(MODELS, { query: 'GLM' })), ['glm-5.3']);
assert.deepEqual(ids(selectModels(MODELS, { query: 'fast gemini' })), ['gemini-3.5-flash']);
assert.deepEqual(ids(selectModels(MODELS, { query: 'grok-4.7' })), ['grok-4.7']);
assert.deepEqual(ids(selectModels(MODELS, { query: 'sg', showExcluded: true })), ['deepseek-v4.1-flash-sg']);
assert.deepEqual(ids(selectModels(MODELS, { query: 'sg' })), [], '被排除的模型在搜索里也遵守隐藏规则');
assert.deepEqual(ids(selectModels(MODELS, { query: '没有这个名字' })), []);

// 能力筛选
assert.deepEqual(ids(selectModels(MODELS, { capability: 'reasoning' })),
                 ['hy4-preview-f', 'glm-5.3', 'grok-4.7', 'gemini-3.5-flash']);
assert.deepEqual(ids(selectModels(MODELS, { capability: 'vision' })), ['hy4-preview-f']);
assert.deepEqual(ids(selectModels(MODELS, { capability: 'tools' })), ['hy4-preview-f', 'glm-5.3']);
assert.deepEqual(ids(selectModels(MODELS, { capability: 'long' })),
                 ['hy4-preview-f', 'glm-5.3', 'grok-4.7', 'gemini-3.5-flash', 'kimi-k2.6']);
assert.equal(LONG_CONTEXT_TOKENS, 128000);
assert.deepEqual(ids(selectModels(MODELS, { query: 'glm', capability: 'vision' })), []);

// 倍率排序：数字与字符串混排，缺倍率的排最后
assert.equal(hasCredits(MODELS), true);
assert.equal(hasCredits([{ id: 'a', enabled: true }]), false);
assert.deepEqual(ids(selectModels(MODELS, { sort: 'credit' })),
                 ['hy4-preview-f', 'kimi-k2.6', 'glm-5.3', 'grok-4.7', 'gemini-3.5-flash']);
assert.deepEqual(ids(selectModels(MODELS, { sort: 'context' })), ['hy4-preview-f', 'glm-5.3', 'gemini-3.5-flash', 'grok-4.7', 'kimi-k2.6']);

// 倍率标签：字符串与数字都要认
assert.equal(creditsValue({ credits: 'x1.90' }), 1.9);
assert.equal(creditsValue({ credits: 0.03 }), 0.03);
assert.equal(creditsValue({ credits: 'n/a' }), null);
assert.equal(creditsValue({}), null);
assert.deepEqual(creditInfo({ id: 'grok-4.7', credits: 'x1.90' }, 'intl'), { label: '1.90x', note: '', free: false });
assert.deepEqual(creditInfo({ id: 'grok-4.7', credits: 1.9 }, 'intl'), { label: '1.9', note: '', free: false });
assert.equal(creditInfo({ id: 'hy4-preview-f', credits: 'x0.00' }, 'intl').free, true);
assert.equal(creditInfo({ id: 'hy3' }, 'intl').free, true, 'hy3 标为限时免费');
assert.equal(creditInfo({ id: 'hy3' }, 'intl').label, '0.00x');
assert.equal(creditInfo({ id: 'deepseek-v4.1-flash', credits: 'x0.03' }, 'intl').free, true);
assert.equal(creditInfo({ id: 'deepseek-v4.1-flash', credits: 'x0.03' }, 'cn').free, false);
assert.deepEqual(creditInfo({ id: 'glm-5.2', credits: 'x0.79' }, 'cn').note, '夜间 0.5x');
assert.equal(creditInfo({ id: 'glm-5.2', credits: 'x0.79' }, 'intl').note, '');
assert.equal(creditInfo({ id: 'kimi-k3' }, 'intl'), null);
assert.deepEqual(creditInfo({ id: 'kimi-k3', credits: 'x0.00' }, 'intl').free, true);

// 统计卡的数字
const stats = summary(MODELS);
assert.deepEqual(stats, { total: 7, enabled: 5, reasoning: 4, longContext: 6, maxContext: 1000000, maxOutput: 128000 });
assert.deepEqual(summary([]), { total: 0, enabled: 0, reasoning: 0, longContext: 0, maxContext: 0, maxOutput: 0 });

// 目录地址：带 refresh=1 时网关跳过缓存
assert.equal(panelModelsUrl('intl'), '/panel/models?realm=intl');
assert.equal(panelModelsUrl('cn', true), '/panel/models?realm=cn&refresh=1');
assert.equal(panelModelsUrl('all'), '/panel/models?realm=all');

// 勾选写回：disabled_models 是「当前没有勾选」的模型 id，取消勾选的模型仍留在表里
assert.deepEqual(disabledIds(MODELS), ['default-model', 'deepseek-v4.1-flash-sg']);
assert.ok(ids(selectModels(withEnabled(MODELS, 'glm-5.3', false), {})).includes('glm-5.3'));
assert.deepEqual(disabledIds(withEnabled(MODELS, 'kimi-k2.6', false)),
                 ['kimi-k2.6', 'default-model', 'deepseek-v4.1-flash-sg']);
assert.deepEqual(disabledIds(withEnabled(MODELS, 'default-model', true)), ['deepseek-v4.1-flash-sg']);
assert.notEqual(withEnabled(MODELS, 'kimi-k2.6', false), MODELS, '返回新数组');
assert.equal(MODELS[4].enabled, true, '不修改传入的数据');

// 分账号查看：账号名单、模型可用性与聚合覆盖
const ACCOUNTS = [
  { uid: 'a', realm: 'intl', enabled: true, disabledModels: ['glm-5.3'] },
  { uid: 'b', realm: 'intl', enabled: true, disabledModels: [] },
  { uid: 'c', realm: 'intl', enabled: false, disabledModels: ['hy3'] },
  { uid: 'd', realm: 'cn', enabled: true, disabledModels: [] },
];
assert.deepEqual(realmAccounts(ACCOUNTS, 'intl').map((a) => a.uid), ['a', 'b', 'c']);
assert.equal(accountCanUse({ id: 'GLM-5.3' }, ACCOUNTS[0]), false, '排除名单大小写不敏感');
assert.equal(accountCanUse({ id: 'glm-5.3' }, ACCOUNTS[1]), true);
assert.deepEqual(coverageFor({ id: 'glm-5.3' }, realmAccounts(ACCOUNTS, 'intl')),
  { can: 1, total: 2, text: '1/2' }, '停用账号不计入覆盖');
assert.deepEqual(coverageFor({ id: 'hy3' }, realmAccounts(ACCOUNTS, 'intl')),
  { can: 2, total: 2, text: '2/2' });
assert.equal(accountAvailableCount(MODELS, ACCOUNTS[0]),
  MODELS.filter((m) => m.enabled && m.id !== 'glm-5.3').length);
assert.equal(accountAvailableCount(MODELS, ACCOUNTS[1]), stats.enabled);

console.log('models logic checks passed');
