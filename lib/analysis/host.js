/**
 * 宿主环境（DOM/BOM）识别与最小桩生成。
 *
 * ## 这个文件要解决的核心问题
 *
 * 抠出来的前端代码之所以在 Node 里跑不起来，是因为它默认自己活在浏览器里：
 * `window`、`document`、`navigator`、`canvas` 全是现成的。想让它变成纯计算函数，
 * 必须先回答两个不同的问题——**混淆点在于它们经常被混为一谈**：
 *
 *   1. **可以去掉的**：只为了与页面交互、上报、渲染而存在的调用（`addEventListener`、
 *      `appendChild`、`sendBeacon`…）。这些对计算结果没有贡献，桩成 no-op 即可。
 *
 *   2. **不能凭空造的**：参与签名计算的环境输入（`navigator.userAgent`、
 *      `screen.width`、canvas 指纹、`performance.now()`…）。这些**必须从真实浏览器里
 *      采集后注入**，任何「模拟一个值」的做法都会算出与目标不一致的签名。
 *
 * 所以本模块的输出不是一个「浏览器模拟器」，而是：
 *   - 一份**引用清单**（谁被引用了、在哪个函数里、属于上面哪一类）；
 *   - 一个**最小 env 工厂**（只含被引用到的全局，no-op 与可计算的部分给真实实现，
 *     必须采集的部分留成显式占位并标注 `MUST_CAPTURE`）。
 *
 * 明确不做的事：不引入 jsdom / happy-dom 之类的浏览器模拟库。理由同上——模拟器会
 * 给出**看似合理但错误**的指纹值，反而把「算错了」伪装成「算对了」。
 */
import { ReverseError } from '../core/errors.js';
import { childNode, childNodes, collect, isReferencePosition, nodeName, strProp, walk, walkDetailed, } from './ast.js';
/**
 * 宿主全局目录。
 *
 * 只收录**在真实混淆代码里高频出现**的项，而不是把浏览器 API 全表抄一遍——
 * 清单越长越难维护，而实际会拦住静态还原的就那几十个。
 */
export const HOST_GLOBALS = [
    // ---- BOM：参与指纹，必须采集 ----
    { name: 'window', category: 'bom', relevance: 'must-capture', note: '宿主根对象；其属性常被直接读取作为环境指纹' },
    { name: 'self', category: 'bom', relevance: 'must-capture', note: 'Worker/主线程下的宿主别名' },
    { name: 'top', category: 'bom', relevance: 'must-capture', note: '常被用来检测是否被 iframe 嵌套' },
    { name: 'parent', category: 'bom', relevance: 'must-capture', note: '常被用来检测是否被 iframe 嵌套' },
    { name: 'navigator', category: 'platform', relevance: 'must-capture', note: 'userAgent/platform/hardwareConcurrency 是典型签名输入' },
    { name: 'screen', category: 'platform', relevance: 'must-capture', note: '宽高/色深参与指纹' },
    { name: 'location', category: 'bom', relevance: 'must-capture', note: 'href/host 常被拼进签名或用于分支' },
    { name: 'history', category: 'bom', relevance: 'removable', note: '仅为导航，计算上无贡献' },
    { name: 'devicePixelRatio', category: 'platform', relevance: 'must-capture', note: '参与 canvas 指纹缩放' },
    { name: 'outerWidth', category: 'platform', relevance: 'must-capture', note: '窗口尺寸参与指纹' },
    { name: 'outerHeight', category: 'platform', relevance: 'must-capture', note: '窗口尺寸参与指纹' },
    { name: 'innerWidth', category: 'platform', relevance: 'must-capture', note: '窗口尺寸参与指纹' },
    { name: 'innerHeight', category: 'platform', relevance: 'must-capture', note: '窗口尺寸参与指纹' },
    // ---- DOM ----
    { name: 'document', category: 'dom', relevance: 'must-capture', note: 'cookie / referrer / 元素内容常参与签名；元素渲染部分可移除' },
    { name: 'HTMLElement', category: 'dom', relevance: 'removable', note: '仅用于类型判断或元素构造' },
    { name: 'Element', category: 'dom', relevance: 'removable', note: '仅用于类型判断' },
    { name: 'Node', category: 'dom', relevance: 'removable', note: '仅用于类型判断' },
    { name: 'Event', category: 'dom', relevance: 'removable', note: '事件对象构造' },
    { name: 'CustomEvent', category: 'dom', relevance: 'removable', note: '自定义事件派发' },
    { name: 'getComputedStyle', category: 'dom', relevance: 'must-capture', note: '样式读取可能参与指纹' },
    { name: 'matchMedia', category: 'dom', relevance: 'must-capture', note: '媒体查询结果参与指纹' },
    // ---- 图形：无法在 Node 中复现 ----
    { name: 'CanvasRenderingContext2D', category: 'graphics', relevance: 'must-capture', note: 'canvas 指纹必须采集真实渲染结果' },
    { name: 'WebGLRenderingContext', category: 'graphics', relevance: 'must-capture', note: 'WebGL 参数指纹必须采集' },
    { name: 'OffscreenCanvas', category: 'graphics', relevance: 'must-capture', note: '离屏 canvas 同样产生指纹' },
    { name: 'AudioContext', category: 'graphics', relevance: 'must-capture', note: '音频指纹必须采集' },
    // ---- 存储 ----
    { name: 'localStorage', category: 'storage', relevance: 'must-capture', note: 'localStorage 里的 token/盐值常参与签名' },
    { name: 'sessionStorage', category: 'storage', relevance: 'must-capture', note: '同上，注意作用域是标签页' },
    { name: 'indexedDB', category: 'storage', relevance: 'removable', note: '异步存储，极少参与同步签名计算' },
    { name: 'document.cookie', category: 'storage', relevance: 'must-capture', note: 'cookie 常直接拼进签名' },
    // ---- 网络：纯副作用 ----
    { name: 'XMLHttpRequest', category: 'network', relevance: 'removable', note: '网络发送，对计算结果无贡献' },
    { name: 'fetch', category: 'network', relevance: 'removable', note: '网络发送，对计算结果无贡献' },
    { name: 'WebSocket', category: 'network', relevance: 'removable', note: '长连接，对计算结果无贡献' },
    { name: 'EventSource', category: 'network', relevance: 'removable', note: 'SSE，对计算结果无贡献' },
    { name: 'RTCPeerConnection', category: 'network', relevance: 'removable', note: '常见于指纹探测，取不到值即为特征' },
    { name: 'sendBeacon', category: 'network', relevance: 'removable', note: '上报，对计算结果无贡献' },
    // ---- 定时：影响时序，可确定性化 ----
    { name: 'setTimeout', category: 'timing', relevance: 'capturable', note: 'Node 有真实实现；若代码依赖它做延时解混淆需注意时序' },
    { name: 'setInterval', category: 'timing', relevance: 'capturable', note: '同上；混淆代码常用它拖延解码' },
    { name: 'clearTimeout', category: 'timing', relevance: 'capturable', note: 'Node 有真实实现' },
    { name: 'clearInterval', category: 'timing', relevance: 'capturable', note: 'Node 有真实实现' },
    { name: 'requestAnimationFrame', category: 'timing', relevance: 'capturable', note: 'Node 无此 API，需桩；通常仅用于渲染' },
    { name: 'cancelAnimationFrame', category: 'timing', relevance: 'capturable', note: '同上' },
    { name: 'performance', category: 'timing', relevance: 'must-capture', note: 'performance.now() 常直接参与签名，需注入采集值与基准' },
    // ---- 加密：Node 有等价能力 ----
    { name: 'crypto', category: 'crypto', relevance: 'capturable', note: 'getRandomValues/randomUUID 在 Node 可复现（注意需固定种子才能得到相同签名）' },
    { name: 'msCrypto', category: 'crypto', relevance: 'capturable', note: '旧版 IE 前缀，同上' },
    { name: 'CryptoJS', category: 'crypto', relevance: 'capturable', note: '第三方库，非宿主 API；应连同库源码一起抽取，而不是桩掉' },
    // ---- 编解码：Node 有真实实现，不要桩 ----
    { name: 'atob', category: 'encoding', relevance: 'capturable', note: 'base64 解码，Node 用 Buffer 实现即可，结果完全一致' },
    { name: 'btoa', category: 'encoding', relevance: 'capturable', note: 'base64 编码，同上' },
    { name: 'TextEncoder', category: 'encoding', relevance: 'capturable', note: 'Node 原生提供' },
    { name: 'TextDecoder', category: 'encoding', relevance: 'capturable', note: 'Node 原生提供' },
    { name: 'URL', category: 'encoding', relevance: 'capturable', note: 'Node 原生提供' },
    { name: 'URLSearchParams', category: 'encoding', relevance: 'capturable', note: 'Node 原生提供' },
    { name: 'Blob', category: 'encoding', relevance: 'removable', note: '二进制容器，多用于上传' },
    { name: 'File', category: 'encoding', relevance: 'removable', note: '文件对象，多用于上传' },
    { name: 'FileReader', category: 'encoding', relevance: 'removable', note: '异步读文件，签名场景少见' },
    { name: 'FormData', category: 'encoding', relevance: 'removable', note: '表单容器' },
    { name: 'Buffer', category: 'encoding', relevance: 'capturable', note: 'Node 原生；若是 browserify 注入的同名 shim 也应以 Node 版为准' },
    // ---- 平台杂项 ----
    { name: 'process', category: 'platform', relevance: 'capturable', note: 'Node 原生；浏览器里通常来自打包工具 shim' },
    { name: 'require', category: 'platform', relevance: 'capturable', note: 'CommonJS 加载器；若代码用它取内置模块需改为 ESM import' },
    { name: 'module', category: 'platform', relevance: 'removable', note: 'CommonJS 模块对象' },
    { name: 'exports', category: 'platform', relevance: 'removable', note: 'CommonJS 导出对象' },
    { name: '__dirname', category: 'platform', relevance: 'removable', note: 'CommonJS 路径变量' },
    { name: 'Worker', category: 'platform', relevance: 'removable', note: '多线程，计算上可用同步方式替代' },
    { name: 'Notification', category: 'platform', relevance: 'removable', note: '通知权限探测，属指纹噪声' },
    { name: 'DOMParser', category: 'dom', relevance: 'removable', note: 'HTML 解析，签名场景少见' },
    { name: 'XMLSerializer', category: 'dom', relevance: 'removable', note: '序列化，签名场景少见' },
    { name: 'MutationObserver', category: 'dom', relevance: 'removable', note: 'DOM 变更监听' },
    { name: 'IntersectionObserver', category: 'dom', relevance: 'removable', note: '可见性监听' },
    { name: 'ResizeObserver', category: 'dom', relevance: 'removable', note: '尺寸监听' },
    // ---- 诊断：可直接 no-op ----
    { name: 'alert', category: 'diagnostic', relevance: 'removable', note: '弹窗' },
    { name: 'confirm', category: 'diagnostic', relevance: 'removable', note: '弹窗' },
    { name: 'prompt', category: 'diagnostic', relevance: 'removable', note: '弹窗' },
    { name: 'console', category: 'diagnostic', relevance: 'diagnostic', note: 'Node 原生 console 即可；若用于反调试需注意' },
    { name: 'debugger', category: 'diagnostic', relevance: 'diagnostic', note: '反调试语句，静态还原时应删除' },
];
/** 名字 → 目录项的索引。 */
const HOST_INDEX = new Map(HOST_GLOBALS.map((spec) => [spec.name, spec]));
/**
 * 判断一个标识符名是否为已知宿主全局。
 *
 * @param name - 标识符名。
 * @returns 目录项，未收录时为 `undefined`。
 */
export function lookupHostGlobal(name) {
    return HOST_INDEX.get(name);
}
/**
 * 收集 binding pattern 里的名字，写入给定集合。
 *
 * @param node - binding pattern 节点。
 * @param target - 目标集合。
 */
function addPatternNames(node, target) {
    if (!node)
        return;
    switch (node.type) {
        case 'Identifier': {
            const name = strProp(node, 'name');
            if (name)
                target.add(name);
            return;
        }
        case 'ObjectPattern':
            for (const property of childNodes(node, 'properties')) {
                if (property.type === 'Property')
                    addPatternNames(childNode(property, 'value'), target);
                else if (property.type === 'RestElement')
                    addPatternNames(childNode(property, 'argument'), target);
            }
            return;
        case 'ArrayPattern':
            for (const element of childNodes(node, 'elements'))
                addPatternNames(element, target);
            return;
        case 'AssignmentPattern':
            addPatternNames(childNode(node, 'left'), target);
            return;
        case 'RestElement':
            addPatternNames(childNode(node, 'argument'), target);
            return;
        default:
            return;
    }
}
/**
 * 构建作用域绑定表（文件根 + 每个函数各一个作用域）。
 *
 * 为什么不能只做「文件级去重」：早先的实现把整份文件里出现过的所有声明名合成一个集合，
 * 于是**任何一处** `var navigator = …` 都会让全文的 `navigator` 都不再被识别为宿主引用
 * ——这是危险的漏检（漏掉的环境依赖会让还原结果悄悄算错）。
 * 改成按作用域判定后，只有真正处在遮蔽范围内的引用才会被排除。
 *
 * @param ast - 根节点。
 * @returns 作用域列表（含根作用域）。
 */
function buildScopeBindings(ast) {
    const root = { start: ast.start, end: ast.end, bindings: new Set() };
    const scopes = [root];
    const functionScopes = new Map();
    const functions = collect(ast).filter((node) => node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression');
    for (const fn of functions) {
        const scope = { start: fn.start, end: fn.end, bindings: new Set() };
        scopes.push(scope);
        functionScopes.set(fn, scope);
    }
    /** 找到包含该偏移的最小作用域；`excludeStart` 用于跳过节点自身的作用域。 */
    const innermost = (offset, excludeStart) => {
        let best = root;
        for (const scope of scopes) {
            if (scope.start === excludeStart)
                continue;
            if (offset < scope.start || offset >= scope.end)
                continue;
            if (scope.end - scope.start < best.end - best.start)
                best = scope;
        }
        return best;
    };
    // 函数参数绑定在函数自己的作用域
    for (const fn of functions) {
        const scope = functionScopes.get(fn);
        if (!scope)
            continue;
        for (const param of childNodes(fn, 'params'))
            addPatternNames(param, scope.bindings);
    }
    walk(ast, (node) => {
        switch (node.type) {
            case 'VariableDeclarator':
                addPatternNames(childNode(node, 'id'), innermost(node.start).bindings);
                break;
            case 'FunctionDeclaration':
            case 'ClassDeclaration':
                // 声明名绑定在**外层**作用域，而不是它自己的作用域
                addPatternNames(childNode(node, 'id'), innermost(node.start, node.start).bindings);
                break;
            case 'FunctionExpression':
            case 'ClassExpression': {
                // 具名函数表达式的名字只在自己内部可见
                const scope = functionScopes.get(node);
                if (scope)
                    addPatternNames(childNode(node, 'id'), scope.bindings);
                break;
            }
            case 'CatchClause':
                addPatternNames(childNode(node, 'param'), innermost(node.start).bindings);
                break;
            case 'ImportDeclaration':
                for (const specifier of childNodes(node, 'specifiers')) {
                    addPatternNames(childNode(specifier, 'local'), root.bindings);
                }
                break;
            default:
                break;
        }
    });
    return scopes;
}
/**
 * 判断某个位置的标识符是否被任一**包含它的**作用域绑定所遮蔽。
 *
 * 包含该偏移的全部作用域恰好构成它的作用域链，因此逐个体检即可。
 *
 * @param scopes - 作用域列表。
 * @param offset - 标识符偏移。
 * @param name - 标识符名。
 * @returns 是否被遮蔽。
 */
function isShadowed(scopes, offset, name) {
    for (const scope of scopes) {
        if (offset < scope.start || offset >= scope.end)
            continue;
        if (scope.bindings.has(name))
            return true;
    }
    return false;
}
/**
 * 收集源码里所有被声明的绑定名（变量、函数、类、参数、catch、import）。
 *
 * 注意：这是**文件级**的扁平集合，只适合回答「这个名字在本文件里是否被声明过」
 * （例如闭包抽取判断某个符号是否存在）。判断「某处引用是否被遮蔽」必须用
 * {@link buildScopeBindings} + {@link isShadowed}，否则会漏检宿主依赖。
 *
 * @param root - 根节点。
 * @returns 被声明的名字集合。
 */
export function collectDeclaredNames(root) {
    const declared = new Set();
    walk(root, (node) => {
        switch (node.type) {
            case 'VariableDeclarator':
                addPatternNames(childNode(node, 'id'), declared);
                break;
            case 'FunctionDeclaration':
            case 'FunctionExpression':
            case 'ArrowFunctionExpression':
                addPatternNames(childNode(node, 'id'), declared);
                for (const param of childNodes(node, 'params'))
                    addPatternNames(param, declared);
                break;
            case 'ClassDeclaration':
            case 'ClassExpression':
                addPatternNames(childNode(node, 'id'), declared);
                break;
            case 'CatchClause':
                addPatternNames(childNode(node, 'param'), declared);
                break;
            case 'ImportDeclaration':
                for (const specifier of childNodes(node, 'specifiers')) {
                    addPatternNames(childNode(specifier, 'local'), declared);
                }
                break;
            default:
                break;
        }
    });
    return declared;
}
/**
 * 找出包含指定偏移的**最小**函数节点，即该位置真正所属的那个函数。
 *
 * 为什么用区间包含而不是遍历时维护函数栈：`walkDetailed` 只有进入没有退出回调，
 * 栈一旦压下就不会回退，归属必然出错。区间判定是无状态的，重复调用也不会互相污染，
 * 因此更可靠。典型规模的源码下开销可忽略。
 *
 * @param functions - 预先收集的函数节点及其范围。
 * @param offset - 待判定的字符偏移。
 * @returns 所属函数的信息。
 */
function findEnclosingFunction(functions, offset) {
    let best;
    for (const fn of functions) {
        if (offset < fn.start || offset >= fn.end)
            continue;
        if (!best || fn.end - fn.start < best.end - best.start)
            best = fn;
    }
    return best ? { name: best.name, line: best.line } : { name: '<top-level>', line: 1 };
}
/**
 * 分析源码里的宿主环境引用。
 *
 * @param ast - 已解析的根节点。
 * @param source - 源码工具。
 * @returns 分析结果。
 */
export function analyzeHostUsage(ast, source) {
    const scopes = buildScopeBindings(ast);
    const references = new Map();
    const functionTouches = new Map();
    // 先收集全部函数范围，后面的归属判定只做区间包含，不依赖遍历顺序。
    const functions = collect(ast)
        .filter((node) => node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression')
        .map((node) => ({
        name: nodeName(node) ?? '<anonymous>',
        line: source.location(node.start).line,
        start: node.start,
        end: node.end,
    }));
    /** 宿主根对象：其静态属性访问等价于「读取同名全局」。 */
    const ROOT_HOST_OBJECTS = new Set(['window', 'self', 'top', 'parent']);
    /**
     * 记一次宿主引用。
     *
     * 抽成局部函数是因为它有两条来源：裸全局标识符（`btoa(...)`），
     * 以及宿主根对象的静态属性（`window.btoa(...)`）。两者都必须记账 ——
     * 生成的 env 会把 `window` 别名到 env 自身，所以 `window.btoa` 取值时
     * 落到 `env.btoa`；只在裸标识符路径记账会让 env 漏掉 `btoa` 实现，
     * 还原产物一跑就是 `TypeError: window.btoa is not a function`。
     */
    const recordReference = (name, node, options = {}) => {
        const spec = lookupHostGlobal(name);
        if (!spec)
            return;
        const location = source.location(node.start);
        const enclosing = findEnclosingFunction(functions, node.start);
        const bucket = references.get(name) ??
            {
                name,
                category: spec.category,
                relevance: spec.relevance,
                note: spec.note,
                count: 0,
                memberPaths: [],
                locations: [],
            };
        bucket.count += 1;
        if (bucket.locations.length < 5) {
            const span = options.snippetNode ?? node;
            bucket.locations.push({
                line: location.line,
                column: location.column,
                snippet: source.snippet(span.start, span.end),
                enclosing: enclosing.name,
            });
        }
        references.set(name, bucket);
        // 记录成员访问路径，如 navigator.userAgent
        const owner = options.memberOwner;
        if (owner) {
            const memberName = nodeName(childNode(owner, 'property') ?? owner);
            const path = memberName ? `${name}.${memberName}` : name;
            if (memberName && !bucket.memberPaths.includes(path) && bucket.memberPaths.length < 12) {
                bucket.memberPaths.push(path);
            }
        }
        const scoreKey = `${enclosing.name}@${enclosing.line}`;
        const score = functionTouches.get(scoreKey) ?? { hostTouches: 0, line: enclosing.line };
        score.hostTouches += 1;
        functionTouches.set(scoreKey, score);
    };
    walkDetailed(ast, (node, parent, key) => {
        // 情况一：`window.btoa` / `self.fetch` 这类宿主根对象的静态属性访问。
        // 非计算属性直接跳过，因为 `window[k]` 的键此时静态不可知。
        if (node.type === 'MemberExpression') {
            if (node.computed === true)
                return;
            const ownerNode = childNode(node, 'object');
            const propertyNode = childNode(node, 'property');
            if (!ownerNode || !propertyNode || propertyNode.type !== 'Identifier')
                return;
            const ownerName = nodeName(ownerNode);
            if (!ownerName || !ROOT_HOST_OBJECTS.has(ownerName))
                return;
            // 局部变量遮蔽了同名根对象时不能按宿主处理
            if (isShadowed(scopes, ownerNode.start, ownerName))
                return;
            const propertyName = strProp(propertyNode, 'name');
            if (!propertyName)
                return;
            recordReference(propertyName, propertyNode, { snippetNode: node });
            return;
        }
        if (node.type !== 'Identifier')
            return;
        const name = strProp(node, 'name');
        if (!name)
            return;
        if (!isReferencePosition(node, parent, key))
            return;
        if (isShadowed(scopes, node.start, name))
            return;
        recordReference(name, node, {
            snippetNode: parent ?? node,
            memberOwner: parent?.type === 'MemberExpression' && key === 'object' ? parent : undefined,
        });
    });
    const list = [...references.values()].sort((a, b) => b.count - a.count);
    const mustCapture = list.filter((item) => item.relevance === 'must-capture').map((item) => item.name);
    const removable = list.filter((item) => item.relevance === 'removable').map((item) => item.name);
    // canvas / WebGL / Audio 这类能力无法在 Node 中合成，必须由调用方采集
    const unmockable = [];
    for (const item of list) {
        for (const path of item.memberPaths) {
            if (/getContext|toDataURL|getParameter|createOscillator/iu.test(path))
                unmockable.push(path);
        }
        if (item.category === 'graphics')
            unmockable.push(item.name);
    }
    const functionScores = [...functionTouches.entries()]
        .map(([key, value]) => ({
        name: key.slice(0, key.lastIndexOf('@')),
        hostTouches: value.hostTouches,
        line: value.line,
    }))
        .sort((a, b) => b.hostTouches - a.hostTouches);
    return {
        references: list,
        mustCapture: [...new Set(mustCapture)],
        removable: [...new Set(removable)],
        unmockable: [...new Set(unmockable)],
        functionScores,
    };
}
/**
 * 生成最小 env 工厂源码。
 *
 * 只包含**实际被引用到**的全局；每个 `must-capture` 项都带 `MUST_CAPTURE` 注释，
 * 提示必须用真实浏览器采集到的值覆盖，否则签名会不一致。
 *
 * @param report - {@link analyzeHostUsage} 的结果。
 * @param options - 生成选项。
 * @returns 桩源码与清单。
 */
export function generateStubs(report, options = {}) {
    const names = report.references.map((item) => item.name);
    const has = (name) => names.includes(name);
    const seed = options.seed ?? 20260101;
    const blocks = [];
    const mustCapture = [];
    // ---- 平台指纹：必须采集 ----
    if (has('navigator')) {
        mustCapture.push('navigator.userAgent', 'navigator.platform', 'navigator.hardwareConcurrency');
        blocks.push(`  navigator: {
    // MUST_CAPTURE: 以下值直接参与签名，必须填入真实浏览器中采集到的值
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    platform: 'MacIntel',
    language: 'zh-CN',
    languages: ['zh-CN', 'zh'],
    vendor: 'Google Inc.',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    cookieEnabled: true,
    webdriver: false,
    plugins: { length: 0, item: () => null, namedItem: () => null, refresh: () => {} },
    mimeTypes: { length: 0, item: () => null, namedItem: () => null },
    userAgentData: undefined,
    mediaDevices: { enumerateDevices: async () => [] },
  },`);
    }
    if (has('screen')) {
        mustCapture.push('screen.width', 'screen.height', 'screen.colorDepth');
        blocks.push(`  screen: { width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, pixelDepth: 30, availLeft: 0, availTop: 0 },`);
    }
    if (has('location')) {
        mustCapture.push('location.href');
        blocks.push(`  location: { href: 'https://example.com/', protocol: 'https:', host: 'example.com', hostname: 'example.com', port: '', pathname: '/', search: '', hash: '', origin: 'https://example.com' },`);
    }
    if (has('performance')) {
        mustCapture.push('performance.timeOrigin', 'performance.now() 的基准');
        blocks.push(`  performance: {
    // MUST_CAPTURE: now() 的绝对值与 timeOrigin 常被直接参与签名；
    // 这里给出可复现的单调递增实现，真实签名请替换为采集值。
    timeOrigin: 1730000000000,
    now: (() => {
      let tick = 0
      return () => {
        tick += 0.1
        return tick
      }
    })(),
    mark: () => {}, measure: () => {}, clearMarks: () => {}, clearMeasures: () => {},
    getEntries: () => [], getEntriesByName: () => [], getEntriesByType: () => [],
  },`);
    }
    if (has('document')) {
        mustCapture.push('document.cookie', 'document.referrer');
        blocks.push(`  document: {
    // MUST_CAPTURE: cookie 与 referrer 常被拼进签名
    cookie: '',
    referrer: '',
    title: '',
    readyState: 'complete',
    characterSet: 'UTF-8',
    charset: 'UTF-8',
    hidden: false,
    visibilityState: 'visible',
    documentElement: { style: {}, clientWidth: 1512, clientHeight: 982, getAttribute: () => null, setAttribute: () => {} },
    body: { style: {}, appendChild: () => {}, removeChild: () => {}, addEventListener: () => {}, removeEventListener: () => {} },
    head: { appendChild: () => {}, removeChild: () => {} },
    createElement: () => createFakeElement(),
    createElementNS: () => createFakeElement(),
    createTextNode: (text) => ({ nodeValue: String(text), textContent: String(text) }),
    createDocumentFragment: () => ({ appendChild: () => {}, childNodes: [] }),
    getElementById: () => null,
    getElementsByTagName: () => [],
    getElementsByClassName: () => [],
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    write: () => {},
    writeln: () => {},
    open: () => ({}),
    close: () => {},
    all: [],
  },`);
    }
    if (has('devicePixelRatio') || has('outerWidth') || has('innerWidth') || has('outerHeight') || has('innerHeight')) {
        for (const name of ['devicePixelRatio', 'outerWidth', 'innerWidth', 'outerHeight', 'innerHeight']) {
            if (!has(name))
                continue;
            mustCapture.push(name);
            const value = name === 'devicePixelRatio' ? '2' : name.toLowerCase().includes('outer') ? '1512' : '1512';
            blocks.push(`  ${name}: ${value},`);
        }
    }
    if (has('history')) {
        blocks.push(`  history: { length: 2, state: null, scrollRestoration: 'auto', back: () => {}, forward: () => {}, go: () => {}, pushState: () => {}, replaceState: () => {} },`);
    }
    // ---- 存储 ----
    for (const storage of ['localStorage', 'sessionStorage']) {
        if (!has(storage))
            continue;
        mustCapture.push(`${storage} 中参与签名的键值`);
        blocks.push(`  ${storage}: createMemoryStorage(),`);
    }
    // ---- 图形：明确标注不可复现 ----
    if (report.unmockable.length > 0) {
        blocks.push(`  // 以下能力无法在 Node 中复现，createFakeElement() 只保证「不抛异常」。
  // 若目标签名包含 canvas/WebGL/audio 指纹，必须采集真实结果后注入：
${report.unmockable.map((item) => `  //   - ${item}`).join('\n')}`);
    }
    // ---- 网络 / 诊断：直接 no-op ----
    const noopGlobals = ['XMLHttpRequest', 'WebSocket', 'EventSource', 'RTCPeerConnection', 'Notification', 'Worker', 'MutationObserver', 'IntersectionObserver', 'ResizeObserver', 'DOMParser', 'AudioContext'];
    for (const name of noopGlobals) {
        if (!has(name))
            continue;
        blocks.push(`  ${name}: createNoopConstructor('${name}'),`);
    }
    for (const name of ['alert', 'confirm', 'prompt']) {
        if (!has(name))
            continue;
        blocks.push(`  ${name}: () => {},`);
    }
    if (has('fetch'))
        blocks.push(`  fetch: async () => ({ ok: false, status: 0, text: async () => '', json: async () => ({}) }),`);
    if (has('sendBeacon'))
        blocks.push(`  sendBeacon: () => true,`);
    if (has('console'))
        blocks.push(`  console,`);
    // ---- 定时 ----
    if (has('setTimeout'))
        blocks.push(`  setTimeout,`);
    if (has('setInterval'))
        blocks.push(`  setInterval,`);
    if (has('clearTimeout'))
        blocks.push(`  clearTimeout,`);
    if (has('clearInterval'))
        blocks.push(`  clearInterval,`);
    if (has('requestAnimationFrame'))
        blocks.push(`  requestAnimationFrame: (callback) => setTimeout(() => callback(Date.now()), 16),`);
    if (has('cancelAnimationFrame'))
        blocks.push(`  cancelAnimationFrame: (handle) => clearTimeout(handle),`);
    if (has('getComputedStyle'))
        blocks.push(`  getComputedStyle: () => ({ getPropertyValue: () => '', width: '0px', height: '0px' }),`);
    if (has('matchMedia'))
        blocks.push(`  matchMedia: (query) => ({ matches: false, media: String(query), addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }),`);
    if (has('TextEncoder'))
        blocks.push(`  TextEncoder,`);
    if (has('TextDecoder'))
        blocks.push(`  TextDecoder,`);
    if (has('URL'))
        blocks.push(`  URL,`);
    if (has('URLSearchParams'))
        blocks.push(`  URLSearchParams,`);
    if (has('Buffer'))
        blocks.push(`  Buffer,`);
    if (has('process'))
        blocks.push(`  process,`);
    if (has('Blob'))
        blocks.push(`  Blob: createNoopConstructor('Blob'),`);
    if (has('File'))
        blocks.push(`  File: createNoopConstructor('File'),`);
    if (has('FileReader'))
        blocks.push(`  FileReader: createNoopConstructor('FileReader'),`);
    if (has('FormData'))
        blocks.push(`  FormData: createNoopConstructor('FormData'),`);
    if (has('indexedDB'))
        blocks.push(`  indexedDB: undefined,`);
    if (has('HTMLElement') || has('Element') || has('Node')) {
        blocks.push(`  HTMLElement: createNoopConstructor('HTMLElement'),
  Element: createNoopConstructor('Element'),
  Node: createNoopConstructor('Node'),`);
    }
    if (has('Event'))
        blocks.push(`  Event: createNoopConstructor('Event'),`);
    if (has('CustomEvent'))
        blocks.push(`  CustomEvent: createNoopConstructor('CustomEvent'),`);
    if (has('XMLSerializer'))
        blocks.push(`  XMLSerializer: createNoopConstructor('XMLSerializer'),`);
    if (has('module'))
        blocks.push(`  module: { exports: {} },`);
    if (has('exports'))
        blocks.push(`  exports: {},`);
    if (has('__dirname'))
        blocks.push(`  __dirname: '',`);
    if (has('require')) {
        blocks.push(`  // require：混淆代码里常用来取内置模块。Node 中应改为 ESM import；
  // 这里给一个最小实现，只支持 node: 前缀与常见内置名。
  require: (id) => {
    throw new Error(\`require(\\\`\${id}\\\`) 不可用：请在纯算代码里改为 import\`)
  },`);
    }
    // ---- 加密 ----
    if (has('crypto') || has('msCrypto')) {
        mustCapture.push('crypto.getRandomValues 的返回值（若参与签名）');
        for (const name of ['crypto', 'msCrypto']) {
            if (!has(name))
                continue;
            blocks.push(`  ${name}: {
    // MUST_CAPTURE: 随机数一旦参与签名，必须固定种子或直接注入采集结果，否则每次结果都不同
    getRandomValues: (typedArray) => {
      const random = createSeededRandom(${seed})
      for (let i = 0; i < typedArray.length; i += 1) typedArray[i] = Math.floor(random() * 256)
      return typedArray
    },
    randomUUID: () => {
      const random = createSeededRandom(${seed + 1})
      const hex = '0123456789abcdef'
      let uuid = ''
      for (let i = 0; i < 32; i += 1) uuid += hex[Math.floor(random() * 16)]
      return \`\${uuid.slice(0, 8)}-\${uuid.slice(8, 12)}-4\${uuid.slice(13, 16)}-a\${uuid.slice(17, 20)}-\${uuid.slice(20)}\`
    },
    subtle: undefined,
  },`);
        }
    }
    // ---- atob / btoa：给真实实现，不要桩 ----
    if (has('atob')) {
        blocks.push(`  // atob/btoa 用 Buffer 实现，结果与浏览器完全一致，属于「可确定复现」而非桩
  atob: (input) => Buffer.from(String(input), 'base64').toString('latin1'),
  btoa: (input) => Buffer.from(String(input), 'latin1').toString('base64'),`);
    }
    else if (has('btoa')) {
        blocks.push(`  btoa: (input) => Buffer.from(String(input), 'latin1').toString('base64'),`);
    }
    const windowReferenced = has('window') || has('self') || has('top') || has('parent');
    const windowAliases = ['window', 'self', 'top', 'parent'].filter(has);
    const aliasComment = windowAliases.length === 0
        ? ''
        : `
  // window/self/top/parent 是宿主根对象。让它们指向 env 自身，
  // 这样源码里 window.navigator 与直接写 navigator 取到同一个对象，
  // 也避免出现「赋值给 window.foo 却读不到」的割裂。
`;
    const aliasLines = windowAliases.map((name) => `  merged.${name} = merged`).join('\n');
    const source = `/**
 * 最小宿主桩 —— 由 dsh-plugin-reverse 生成，请勿手工大改（重建会覆盖）。
 *
 * 设计意图：**这不是浏览器模拟器**。它只提供被源码引用到的那部分宿主对象，
 * 并且刻意区分三种情况：
 *
 *   - 可确定复现的（atob/btoa/setTimeout/TextEncoder…）→ 给真实实现，结果与浏览器一致
 *   - 纯副作用（fetch/addEventListener/appendChild…）→ no-op，不影响计算结果
 *   - MUST_CAPTURE（navigator/screen/cookie/canvas 指纹…）→ 留显式占位
 *
 * 第三类是静态还原的**真正边界**：这些值参与签名，且依赖真实浏览器实例。
 * 不要试图「编一个合理的值」——那只会得到一个看起来对、实际错的签名。
 * 正确做法是在浏览器里采集一次，然后通过 createEnv({ ... }) 注入。
 */

/** 确定性伪随机（xorshift32），用于让随机数参与的计算可复现。 */
export function createSeededRandom(seed) {
  let state = seed >>> 0 || 1
  return () => {
    state ^= state << 13; state >>>= 0
    state ^= state >>> 17
    state ^= state << 5; state >>>= 0
    return state / 4294967296
  }
}

/** 内存版 Storage，行为对齐浏览器（字符串键值 + 自动转字符串）。 */
function createMemoryStorage() {
  const map = new Map()
  return {
    get length() { return map.size },
    key: (index) => [...map.keys()][index] ?? null,
    getItem: (key) => (map.has(String(key)) ? map.get(String(key)) : null),
    setItem: (key, value) => { map.set(String(key), String(value)) },
    removeItem: (key) => { map.delete(String(key)) },
    clear: () => map.clear(),
  }
}

/** 生成一个「不抛异常」的假元素，仅用于让 DOM 调用链跑通。 */
function createFakeElement(tagName = 'div') {
  const element = {
    tagName: String(tagName).toUpperCase(),
    nodeName: String(tagName).toUpperCase(),
    style: new Proxy({}, { get: () => '', set: () => true }),
    dataset: {},
    children: [],
    childNodes: [],
    attributes: {},
    width: 300,
    height: 150,
    clientWidth: 300,
    clientHeight: 150,
    offsetWidth: 300,
    offsetHeight: 150,
    setAttribute: () => {},
    getAttribute: () => null,
    removeAttribute: () => {},
    hasAttribute: () => false,
    appendChild: (child) => child,
    removeChild: (child) => child,
    insertBefore: (child) => child,
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    getBoundingClientRect: () => ({ x: 0, y: 0, width: 300, height: 150, top: 0, left: 0, right: 300, bottom: 150 }),
    // canvas 相关：无法复现，返回 null / 空串并保持不抛错
    getContext: () => null,
    toDataURL: () => '',
    toBlob: () => {},
    focus: () => {},
    blur: () => {},
    click: () => {},
    remove: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    getElementsByTagName: () => [],
  }
  element.ownerDocument = undefined
  return element
}

/** 生成一个可被 new 调用且不抛异常的占位构造器。 */
function createNoopConstructor(name) {
  function Placeholder() {
    return new Proxy(this, {
      get: (target, key) => {
        if (key in target) return target[key]
        return () => undefined
      },
    })
  }
  Object.defineProperty(Placeholder, 'name', { value: String(name) })
  Placeholder.prototype = new Proxy(Placeholder.prototype, {
    get: (target, key) => {
      if (key in target) return target[key]
      return () => undefined
    },
  })
  return Placeholder
}

/**
 * 创建宿主环境对象。
 *
 * @param overrides - 需要覆盖的部分；**MUST_CAPTURE 的值应当在这里注入真实采集结果**。
 * @returns 宿主环境对象。
 */
export function createEnv(overrides = {}) {
  const env = {
${blocks.join('\n')}
  }
${aliasComment}  const merged = Object.assign(env, overrides)
${aliasLines}${aliasLines ? '\n' : ''}  return merged
}

export default createEnv
`;
    return {
        source,
        mustCapture: [...new Set(mustCapture)],
        unmockable: report.unmockable,
        injected: names,
    };
}
/**
 * 校验宿主报告非空。
 *
 * @param report - 报告。
 */
export function assertHasHostReferences(report) {
    if (report.references.length === 0) {
        throw new ReverseError('未在该源码中发现任何已知宿主 API 引用：要么它已经是纯计算代码，' +
            '要么入口文件不是宿主交互的那一层（例如只是被引入的算法库）。', 'NOT_FOUND');
    }
}
