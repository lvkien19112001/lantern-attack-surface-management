/* Lantern - cài đặt người dùng (lưu trong trình duyệt, áp dụng ngay, dùng chung cho mọi trang).
   Nạp ở <head> bằng thẻ script thường (không defer) để chủ đề được áp dụng trước khi vẽ trang, tránh bị nháy sáng/tối. */
(function () {
  var KEY = 'lantern-settings';
  var DEFAULTS = {
    theme: 'system',        // system | light | dark
    accent: 'teal',         // teal | blue | violet | orange | rose
    density: 'comfortable', // comfortable | compact
    fontSize: 'md',         // sm | md | lg
    reduceMotion: null,     // null = theo hệ điều hành | true | false
    lang: 'vi',             // vi | en
    timeFormat: 'auto',     // auto | 24 | 12
    startPage: 'ov',        // trang mở đầu tiên sau khi đăng nhập
    refresh: 30,            // giây, 0 = tắt tự làm mới khi rảnh
    showClosed: false,      // mặc định hiện phát hiện đã xử lý
    confirmActions: true,   // hỏi xác nhận trước thao tác xóa / đánh dấu hàng loạt
    evBadge: true           // chấm đỏ ở mục Giám sát khi có thay đổi mới
  };
  var ENUM = {
    theme: ['system', 'light', 'dark'], accent: ['teal', 'blue', 'violet', 'orange', 'rose'],
    density: ['comfortable', 'compact'], fontSize: ['sm', 'md', 'lg'], lang: ['vi', 'en'],
    timeFormat: ['auto', '24', '12'], refresh: [0, 15, 30, 60, 300],
    startPage: ['ov', 'as', 'sb', 'po', 'cv', 'fi', 'sc', 'sk', 'ev', 'rp']
  };
  var cur = load(), listeners = [];
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function load() {
    var o = {}, k, raw = null;
    try { raw = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch (e) {}
    for (k in DEFAULTS) o[k] = DEFAULTS[k];
    if (raw && typeof raw === 'object') for (k in DEFAULTS) if (k in raw && valid(k, raw[k])) o[k] = raw[k];
    return o;
  }
  function valid(k, v) {
    if (k === 'reduceMotion') return v === null || typeof v === 'boolean';
    if (typeof DEFAULTS[k] === 'boolean') return typeof v === 'boolean';
    return ENUM[k] ? ENUM[k].indexOf(v) >= 0 : true;
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(cur)); } catch (e) {} }
  function systemDark() { return !!(mq && mq.matches); }
  function reduced() { return cur.reduceMotion === null ? !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) : cur.reduceMotion; }

  function apply() {
    var r = document.documentElement;
    r.setAttribute('data-theme', cur.theme === 'system' ? (systemDark() ? 'dark' : 'light') : cur.theme);
    r.setAttribute('data-accent', cur.accent);
    r.setAttribute('data-density', cur.density);
    r.setAttribute('data-fs', cur.fontSize);
    r.setAttribute('data-motion', reduced() ? 'reduce' : 'full');
    if (r.hasAttribute('data-translated')) r.setAttribute('lang', cur.lang);   // chỉ trang đã có bản dịch
  }
  if (mq) (mq.addEventListener ? mq.addEventListener('change', function () { if (cur.theme === 'system') apply(); })
                               : mq.addListener(function () { if (cur.theme === 'system') apply(); }));
  apply();

  window.LP = {
    DEFAULTS: DEFAULTS,
    get: function (k) { return k ? cur[k] : Object.assign({}, cur); },
    set: function (k, v) {
      if (!(k in DEFAULTS) || !valid(k, v) || cur[k] === v) return;
      cur[k] = v; save(); apply();
      listeners.forEach(function (f) { try { f(k, v); } catch (e) {} });
    },
    reset: function () {
      cur = Object.assign({}, DEFAULTS); save(); apply();
      listeners.forEach(function (f) { try { f('*', null); } catch (e) {} });
    },
    reducedMotion: reduced,
    onChange: function (f) { listeners.push(f); }
  };
  // đồng bộ giữa các tab đang mở
  window.addEventListener('storage', function (e) {
    if (e.key !== KEY) return;
    cur = load(); apply();
    listeners.forEach(function (f) { try { f('*', null); } catch (_) {} });
  });
})();
