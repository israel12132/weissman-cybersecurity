/* eslint-disable -- auto-generated engine ported verbatim from the verified prototype */
/* @weissman-forensic-page
 * AUTO-PORTED from the verified Weissman Command Center prototype.
 * Full-screen immersive Nebula command deck + war room. Live-data engine,
 * three.js glass globe, bilingual (EN/HE), menu + back navigation.
 * Regenerate via scratchpad/gen_engine.py — do not hand-edit the strings. */

export const CC_CSS = `
  #deck,#deck *{box-sizing:border-box;}
  #deck{position:fixed;inset:0;overflow:hidden;}
  #deck[dir="rtl"]{--font-display:'Heebo';--font-body:'Heebo';}

  #bg{position:absolute;inset:0;z-index:0;pointer-events:none;background-color:#2b2467;}
  #brandbg,#veil,#aurora,#grain{position:absolute;inset:0;pointer-events:none;}
  #brandbg{background-image:url("/brand-cover.jpg");background-repeat:no-repeat;background-position:center 24%;
    background-size:cover;transition:opacity .5s ease;}
  #grain{opacity:.05;mix-blend-mode:overlay;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='0.55'/%3E%3C/svg%3E");}
  .logo{width:44px;height:44px;border-radius:12px;flex:0 0 auto;overflow:hidden;position:relative;
    box-shadow:0 0 0 1px var(--edge2),0 6px 18px -6px rgba(23,10,60,.5),0 0 22px -4px var(--a1);}
  .logo::after{content:'';position:absolute;inset:0;border-radius:12px;pointer-events:none;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.35);background:linear-gradient(160deg,rgba(255,255,255,.14),transparent 55%);}
  .logo img{width:100%;height:100%;object-fit:cover;object-position:50% 30%;transform:scale(1.28);display:block;}
  #content{position:absolute;inset:0;z-index:1;overflow-y:auto;overflow-x:hidden;
    padding:0 clamp(14px,2.2vw,30px) 34px;color:var(--text);}
  .warm{position:absolute;inset:0;opacity:0;transition:opacity .8s ease;
    background:radial-gradient(900px 640px at 78% 24%, rgba(244,63,94,.30), transparent 60%),
      radial-gradient(760px 560px at 30% 70%, rgba(245,158,11,.24), transparent 62%);}

  /* ══ THEME · DAYLIGHT ══ */
  #deck[data-dir="daylight"]{--text:#0f172a;--muted:#5b6784;--a1:#0891b2;--a2:#4f46e5;--a3:#7c3aed;
    --ok:#10b981;--warn:#f59e0b;--crit:#e11d48;--radius:18px;
    --font-display:'Space Grotesk';--font-body:'IBM Plex Sans';--font-mono:'IBM Plex Mono';
    --surface:linear-gradient(180deg,rgba(255,255,255,.90),rgba(255,255,255,.66));
    --edge:rgba(255,255,255,.92);--edge2:rgba(120,140,200,.16);
    --shadow:0 14px 34px -14px rgba(28,40,90,.20),0 3px 10px -5px rgba(28,40,90,.12);
    --track:rgba(41,55,99,.08);--hairline:rgba(41,55,99,.12);
    --plate:radial-gradient(circle at 50% 36%, #f8fbff 0%, #eaf0fb 60%, #e3e9f6 100%);
    --map-land:rgba(118,138,214,.55);--map-lit:#22d3ee;--map-grid:rgba(99,102,241,.12);}
  #deck[data-dir="daylight"] #bg{background-color:#eef1f7;background-image:linear-gradient(180deg,#f4f7fd 0%,#eaeef7 46%,#eef1f9 100%);}
  #deck[data-dir="daylight"] #brandbg{opacity:1;filter:brightness(1.08) saturate(1.06) contrast(1.02);}
  #deck[data-dir="daylight"] #veil{background:linear-gradient(180deg,rgba(240,243,250,.60) 0%,rgba(235,239,248,.52) 55%,rgba(238,241,249,.58) 100%);}
  #deck[data-dir="daylight"] #aurora{background-image:
    radial-gradient(1200px 820px at 10% -10%, rgba(34,211,238,.18), transparent 60%),
    radial-gradient(1050px 720px at 90% 2%, rgba(139,92,246,.16), transparent 62%),
    radial-gradient(1400px 1000px at 50% 118%, rgba(99,102,241,.14), transparent 60%);}

  /* ══ THEME · HOLO ══ */
  #deck[data-dir="holo"]{--text:#1b2138;--muted:#5a6488;--a1:#0891b2;--a2:#6366f1;--a3:#8b5cf6;
    --ok:#12a878;--warn:#e0952a;--crit:#e5484d;--radius:18px;
    --font-display:'Space Grotesk';--font-body:'Inter Tight';--font-mono:'IBM Plex Mono';
    --surface:linear-gradient(157deg,rgba(255,255,255,.74),rgba(244,247,255,.52) 48%,rgba(232,238,255,.60));
    --edge:rgba(255,255,255,.85);--edge2:rgba(99,102,241,.16);
    --shadow:0 22px 55px -28px rgba(76,86,160,.42),0 2px 10px -4px rgba(99,102,241,.20);
    --track:rgba(76,86,160,.10);--hairline:rgba(99,102,241,.16);
    --plate:radial-gradient(circle at 50% 34%, #fbfdff 0%, #eef2fe 58%, #e5ebfb 100%);
    --map-land:rgba(99,102,241,.42);--map-lit:#0891b2;--map-grid:rgba(99,102,241,.14);}
  #deck[data-dir="holo"] #bg{background-color:#eef1fb;background-image:linear-gradient(158deg,#f4f6ff 0%,#e7ecfb 46%,#e2e8fa 74%,#edf0fd 100%);}
  #deck[data-dir="holo"] #brandbg{opacity:1;filter:brightness(1.05) saturate(1.16) contrast(1.03);}
  #deck[data-dir="holo"] #veil{background:linear-gradient(180deg,rgba(240,243,252,.54) 0%,rgba(231,237,251,.5) 55%,rgba(237,240,253,.54) 100%);}
  #deck[data-dir="holo"] #aurora{background-image:
    radial-gradient(120% 90% at 12% -8%, rgba(34,211,238,.24), transparent 42%),
    radial-gradient(110% 95% at 92% 4%, rgba(139,92,246,.26), transparent 46%),
    radial-gradient(140% 120% at 50% 116%, rgba(99,102,241,.2), transparent 55%);}

  /* ══ THEME · LIVING NEBULA (default · emphasized) ══ */
  #deck[data-dir="nebula"]{--text:#ffffff;--muted:#d9d2ff;--a1:#3ee9ff;--a2:#a5b4fc;--a3:#e0b3ff;
    --ok:#4ade80;--warn:#fcd34d;--crit:#ff6b81;--radius:20px;
    --font-display:'Bricolage Grotesque';--font-body:'IBM Plex Sans';--font-mono:'Martian Mono';
    --surface:linear-gradient(160deg,rgba(48,40,108,.68),rgba(30,25,74,.56));
    --edge:rgba(190,180,255,.34);--edge2:rgba(165,155,240,.22);
    --shadow:0 24px 70px -24px rgba(20,8,54,.6),inset 0 1px 0 rgba(255,255,255,.3);
    --track:rgba(18,13,52,.52);--hairline:rgba(199,193,240,.26);
    --plate:transparent;--map-land:#3ee9ff;--map-lit:#e0b3ff;--map-grid:rgba(165,180,252,.24);}
  #deck[data-dir="nebula"] #bg{background-color:#2b2467;background-image:linear-gradient(142deg,#2b2467 0%,#3a2a74 40%,#4a2d7c 70%,#362566 100%);}
  #deck[data-dir="nebula"] #brandbg{opacity:.8;mix-blend-mode:screen;filter:saturate(1.4) brightness(1.05) contrast(1.06);}
  #deck[data-dir="nebula"] #veil{background:linear-gradient(160deg,rgba(30,22,74,.30) 0%,rgba(40,28,92,.22) 55%,rgba(34,23,80,.32) 100%);}
  #deck[data-dir="nebula"] #aurora{background-image:
    radial-gradient(1200px 900px at 16% 10%, rgba(34,211,238,.4), transparent 55%),
    radial-gradient(1150px 820px at 84% 18%, rgba(139,92,246,.46), transparent 58%),
    radial-gradient(1350px 1000px at 62% 92%, rgba(236,72,153,.34), transparent 60%),
    radial-gradient(1000px 760px at 24% 80%, rgba(99,102,241,.42), transparent 62%);}
  #deck[data-dir="nebula"] #aurora::after{content:'';position:absolute;inset:-10%;
    background:radial-gradient(700px 520px at 30% 30%, rgba(34,211,238,.16), transparent 60%),
      radial-gradient(680px 500px at 72% 66%, rgba(224,179,255,.16), transparent 62%);
    animation:breathe 42s ease-in-out infinite;}
  @keyframes breathe{0%,100%{transform:translate(0,0) scale(1);}50%{transform:translate(2.5%,-2%) scale(1.05);}}
  /* Nebula emphasis: lift text + numbers off the busy branded ground (cool-navy glow, never black) */
  #deck[data-dir="nebula"] .kpi .k-val,#deck[data-dir="nebula"] .ch .ht b,#deck[data-dir="nebula"] .metric,
  #deck[data-dir="nebula"] .theater-title,#deck[data-dir="nebula"] .mc .grade .g,#deck[data-dir="nebula"] .wr-title,
  #deck[data-dir="nebula"] .brand .wm b{text-shadow:0 1px 16px rgba(16,8,44,.62),0 0 2px rgba(16,8,44,.5);}
  #deck[data-dir="nebula"] .card,#deck[data-dir="nebula"] .kpi{border:1px solid var(--edge2);
    box-shadow:0 26px 70px -26px rgba(16,6,48,.72),inset 0 1px 0 rgba(255,255,255,.16);}
  #deck[data-dir="nebula"] .k-lab,#deck[data-dir="nebula"] .ch .ht .rt,#deck[data-dir="nebula"] .eyebrow{color:#c3bbf5;}

  /* ══ Command bar (shared) ══ */
  .cbar{position:sticky;top:0;z-index:60;display:flex;align-items:center;gap:12px;flex-wrap:wrap;
    padding:12px 0;margin-bottom:8px;padding-top:calc(12px + env(safe-area-inset-top,0px));}
  .cbar::after{content:'';position:absolute;left:-40px;right:-40px;top:0;bottom:0;z-index:-1;
    background:var(--surface);backdrop-filter:blur(22px) saturate(155%);-webkit-backdrop-filter:blur(22px) saturate(155%);
    border-bottom:1px solid var(--edge2);}
  .brand{display:flex;align-items:center;gap:12px;min-width:0;}
  .brand .wm b{font-family:var(--font-display);font-weight:600;letter-spacing:.12em;font-size:15px;color:var(--text);display:block;}
  .brand .wm span{font-family:var(--font-mono);font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:var(--muted);}
  #deck[dir="rtl"] .brand .wm span,#deck[dir="rtl"] .brand .wm b{letter-spacing:0;}
  .iconbtn{display:inline-flex;align-items:center;gap:7px;font-family:var(--font-display);font-weight:500;font-size:12px;
    color:var(--text);background:var(--track);border:1px solid var(--edge2);border-radius:10px;padding:8px 13px;cursor:pointer;
    transition:.16s;white-space:nowrap;}
  .iconbtn:hover{border-color:var(--a1);color:var(--a1);}
  .iconbtn:disabled{opacity:.4;cursor:default;}
  .iconbtn .ic{font-size:14px;line-height:1;}
  .search{flex:1 1 200px;min-width:130px;max-width:460px;display:flex;align-items:center;gap:9px;
    background:var(--track);border:1px solid var(--edge2);border-radius:11px;padding:9px 13px;}
  .search input{flex:1;border:none;background:transparent;color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none;min-width:0;}
  .search input::placeholder{color:var(--muted);}
  .pills{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
  .pill{display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:10px;color:var(--muted);
    background:var(--track);border:1px solid var(--edge2);border-radius:20px;padding:5px 11px;letter-spacing:.03em;}
  .pill i{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);animation:blink 1.7s infinite;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
  #clock{color:var(--a1);font-weight:600;}
  .themeswitch{display:flex;gap:5px;background:var(--track);border:1px solid var(--edge2);border-radius:11px;padding:4px;}
  .themeswitch button{font-family:var(--font-display);font-weight:500;font-size:11px;color:var(--muted);
    background:transparent;border:none;padding:6px 10px;border-radius:8px;cursor:pointer;transition:.16s;white-space:nowrap;}
  .themeswitch button:hover{color:var(--text);}
  .themeswitch button.on{color:#fff;background:linear-gradient(120deg,var(--a1),var(--a2));box-shadow:0 3px 12px -3px var(--a2);}
  .incident-btn{font-family:var(--font-display);font-weight:600;font-size:11px;letter-spacing:.05em;text-transform:uppercase;
    color:#fff;background:linear-gradient(120deg,var(--crit),var(--warn));border:none;padding:9px 14px;border-radius:10px;cursor:pointer;
    box-shadow:0 4px 16px -4px var(--crit);transition:.16s;}
  .incident-btn:hover{transform:translateY(-1px);}

  .eyebrow{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.28em;text-transform:uppercase;color:var(--muted);}

  /* ══ Views ══ */
  .view{display:none;}
  .view.on{display:block;}

  /* KPI ledger */
  .ledger{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:6px 0 14px;}
  .kpi{background:var(--surface);border:1px solid var(--edge);border-radius:14px;padding:12px 14px;position:relative;overflow:hidden;box-shadow:var(--shadow);}
  .kpi .k-lab{font-family:var(--font-mono);font-size:8.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);}
  .kpi .k-val{font-family:var(--font-mono);font-weight:600;font-size:26px;color:var(--text);margin-top:5px;font-variant-numeric:tabular-nums;line-height:1;}
  .kpi .k-delta{font-family:var(--font-mono);font-size:10px;margin-top:5px;}
  .kpi svg{position:absolute;right:8px;bottom:8px;opacity:.9;}
  #deck[dir="rtl"] .kpi svg{right:auto;left:8px;}

  .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;}
  .card{background:var(--surface);border:1px solid var(--edge);border-radius:var(--radius);box-shadow:var(--shadow);
    position:relative;overflow:hidden;display:flex;flex-direction:column;min-width:0;}
  .ch{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 15px;border-bottom:1px solid var(--edge2);}
  .ch .ht{display:flex;flex-direction:column;gap:2px;min-width:0;}
  .ch .ht b{font-family:var(--font-display);font-weight:600;font-size:13px;letter-spacing:.02em;color:var(--text);}
  .ch .ht .rt{font-family:var(--font-mono);font-size:8.5px;letter-spacing:.1em;color:var(--muted);text-transform:uppercase;}
  .ch .live-n{font-family:var(--font-mono);font-size:11px;color:var(--a1);font-variant-numeric:tabular-nums;white-space:nowrap;}
  .open{font-family:var(--font-mono);font-size:9px;color:var(--muted);border:1px solid var(--edge2);border-radius:6px;padding:3px 7px;text-decoration:none;transition:.15s;white-space:nowrap;cursor:pointer;}
  .open:hover{color:var(--a2);border-color:var(--a2);}
  .cbody{padding:13px 15px;flex:1;min-height:0;min-width:0;}
  .s3{grid-column:span 3;} .s4{grid-column:span 4;} .s6{grid-column:span 6;} .s12{grid-column:span 12;}
  .hero-row .card{min-height:410px;}

  #theater{position:relative;padding:0;overflow:hidden;}
  #theater .plate{position:absolute;inset:0;background:var(--plate);}
  #mapCanvas,#globeCanvas{position:absolute;inset:0;width:100%;height:100%;display:block;}
  #globeCanvas{cursor:grab;} #globeCanvas:active{cursor:grabbing;}
  .theater-hud{position:absolute;left:14px;top:12px;right:14px;display:flex;justify-content:space-between;pointer-events:none;z-index:3;}
  .theater-title{font-family:var(--font-display);font-weight:600;font-size:13px;letter-spacing:.05em;color:var(--text);}
  .theater-sub{font-family:var(--font-mono);font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-top:2px;}
  .warp-btn{position:absolute;left:50%;bottom:14px;transform:translateX(-50%);z-index:4;pointer-events:auto;
    font-family:var(--font-display);font-weight:600;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#fff;
    background:linear-gradient(120deg,var(--a1),var(--a2),var(--a3));border:none;padding:10px 20px;border-radius:10px;cursor:pointer;
    box-shadow:0 6px 22px -6px var(--a2);}
  .warp-btn:disabled{opacity:.55;}
  .lockcard{position:absolute;z-index:6;bottom:56px;left:14px;pointer-events:none;
    background:var(--surface);border:1px solid var(--crit);border-radius:12px;padding:11px 14px;max-width:280px;box-shadow:var(--shadow);
    opacity:0;transform:translateY(8px);transition:.35s;}
  .lockcard.on{opacity:1;transform:translateY(0);}
  .lockcard .lt{font-family:var(--font-display);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--crit);}
  .lockcard .ld{font-family:var(--font-mono);font-size:14px;color:var(--text);margin:5px 0;}
  .lockcard .lg{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-family:var(--font-mono);font-size:10px;color:var(--muted);}
  .lockcard .lg b{color:var(--a1);font-weight:500;}

  .stream{display:flex;flex-direction:column;gap:8px;overflow-y:auto;height:100%;padding-right:4px;}
  .cx{background:var(--track);border:1px solid var(--edge2);border-radius:10px;padding:8px 10px;}
  .cx .cxh{display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:9px;color:var(--muted);}
  .cx .cxm{font-size:12px;color:var(--text);margin:4px 0;line-height:1.35;}
  .cx .cxm b{color:var(--a2);font-weight:600;}
  .cx.esc{border-color:var(--crit);background:color-mix(in srgb,var(--crit) 10%,transparent);}
  .cx.esc .cxm b{color:var(--crit);}
  .conf{height:4px;border-radius:3px;background:var(--track);overflow:hidden;margin-top:5px;}
  .conf i{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,var(--a1),var(--a2));}

  .council{display:flex;flex-direction:column;gap:9px;overflow-y:auto;height:100%;}
  .cc{display:flex;align-items:center;gap:11px;background:var(--track);border:1px solid var(--edge2);border-radius:11px;padding:9px 11px;}
  .ccring{width:34px;height:34px;border-radius:50%;flex:0 0 auto;display:grid;place-items:center;background:conic-gradient(var(--a2) var(--p,40%),var(--track) 0);}
  .ccring b{width:26px;height:26px;border-radius:50%;background:var(--surface);display:grid;place-items:center;font-family:var(--font-mono);font-size:9px;color:var(--text);}
  .cc .ccm{flex:1;min-width:0;}
  .cc .ccm .t{font-family:var(--font-mono);font-size:11px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .cc .ccm .s{font-family:var(--font-mono);font-size:9px;color:var(--muted);}
  .cc .act{display:flex;gap:5px;}
  .cc .act button{font-family:var(--font-mono);font-size:9px;border-radius:6px;padding:4px 7px;cursor:pointer;border:1px solid var(--edge2);background:var(--track);color:var(--muted);}
  .cc .act .ok{color:var(--ok);border-color:var(--ok);}

  canvas.viz{display:block;width:100%;height:100%;}
  .vizbox{position:relative;flex:1;min-height:150px;}
  .timeline{display:flex;flex-direction:column;gap:7px;overflow-y:auto;max-height:190px;}
  .heal{display:flex;align-items:center;gap:9px;font-family:var(--font-mono);font-size:11px;}
  .heal .hs{width:8px;height:8px;border-radius:50%;flex:0 0 auto;}
  .heal .ht2{flex:1;min-width:0;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .heal .hd{color:var(--ok);}
  .heatgrid{display:grid;gap:3px;}
  .heatcell{aspect-ratio:1;border-radius:3px;background:var(--track);}
  .radarwrap{display:grid;place-items:center;}

  .ftable{width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;}
  .ftable th{text-align:left;color:var(--muted);font-weight:500;font-size:9px;letter-spacing:.1em;text-transform:uppercase;padding:7px 10px;border-bottom:1px solid var(--edge2);position:sticky;top:0;background:var(--surface);}
  #deck[dir="rtl"] .ftable th{text-align:right;}
  .ftable td{padding:8px 10px;border-bottom:1px solid var(--edge2);color:var(--text);white-space:nowrap;}
  .ftable td.tgt{max-width:180px;overflow:hidden;text-overflow:ellipsis;}
  .ftable tr.flash{animation:rowflash 1.6s ease;}
  @keyframes rowflash{0%{background:color-mix(in srgb,var(--crit) 22%,transparent);}100%{background:transparent;}}
  .sev{display:inline-flex;align-items:center;gap:6px;}
  .sev i{width:8px;height:8px;border-radius:50%;}
  .sev.c i{background:var(--crit);box-shadow:0 0 8px var(--crit);} .sev.h i{background:var(--warn);}
  .sev.m i{background:var(--a2);} .sev.l i{background:var(--muted);}
  .tag{font-family:var(--font-mono);font-size:9px;color:var(--a2);border:1px solid var(--edge2);border-radius:5px;padding:1px 6px;}
  .status-ok{color:var(--ok);} .status-run{color:var(--warn);}
  .mc{display:flex;flex-direction:column;gap:10px;}
  .mc .grade{display:flex;align-items:baseline;gap:10px;}
  .mc .grade .g{font-family:var(--font-display);font-weight:700;font-size:44px;color:var(--ok);line-height:1;}
  .mc .grade .gd{font-family:var(--font-mono);font-size:11px;color:var(--muted);}
  .mc .risks{display:flex;flex-direction:column;gap:6px;}
  .mc .rk{display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:11px;color:var(--text);}
  .mc .rk span:last-child{color:var(--crit);}
  .footnote{margin:18px 0 4px;font-family:var(--font-mono);font-size:10px;color:var(--muted);text-align:center;letter-spacing:.04em;}
  .footnote b{color:var(--a2);}

  /* ══ Menu drawer ══ */
  #scrim{position:fixed;inset:0;z-index:70;background:rgba(20,10,50,.55);backdrop-filter:blur(3px);opacity:0;pointer-events:none;transition:.25s;}
  #scrim.on{opacity:1;pointer-events:auto;}
  #menu{position:fixed;top:0;bottom:0;left:0;z-index:80;width:min(340px,86vw);transform:translateX(-104%);
    transition:transform .3s cubic-bezier(.2,.8,.2,1);background:linear-gradient(180deg,rgba(30,24,74,.96),rgba(22,17,58,.98));
    backdrop-filter:blur(26px);border-right:1px solid var(--edge);overflow-y:auto;padding:16px 14px calc(24px + env(safe-area-inset-bottom,0px));
    padding-top:calc(16px + env(safe-area-inset-top,0px));box-shadow:30px 0 80px -20px rgba(10,4,40,.7);}
  #deck[dir="rtl"] #menu{left:auto;right:0;transform:translateX(104%);border-right:none;border-left:1px solid var(--edge);}
  #menu.on{transform:translateX(0);}
  .menu-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;}
  .menu-head .mt{font-family:var(--font-display);font-weight:600;font-size:15px;letter-spacing:.1em;color:#fff;}
  .menu-x{width:32px;height:32px;border-radius:9px;border:1px solid var(--edge2);background:var(--track);color:#fff;cursor:pointer;font-size:16px;}
  .launch{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:16px;}
  .launch button{display:flex;flex-direction:column;gap:5px;align-items:flex-start;font-family:var(--font-display);font-weight:600;font-size:13px;
    color:#fff;border:1px solid var(--edge2);border-radius:13px;padding:13px 13px;cursor:pointer;text-align:left;transition:.16s;
    background:linear-gradient(150deg,rgba(62,233,255,.14),rgba(165,180,252,.1));}
  #deck[dir="rtl"] .launch button{text-align:right;align-items:flex-end;}
  .launch button:hover{border-color:var(--a1);transform:translateY(-1px);}
  .launch button.on{background:linear-gradient(120deg,var(--a1),var(--a2));color:#08122a;}
  .launch button .li{font-size:19px;}
  .launch button small{font-family:var(--font-mono);font-size:8.5px;letter-spacing:.14em;text-transform:uppercase;opacity:.8;font-weight:400;}
  .menu-group{margin-bottom:6px;}
  .menu-group>.gt{font-family:var(--font-mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--a2);padding:9px 8px 5px;}
  .menu-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:9px;color:#e7e3ff;font-family:var(--font-body);font-size:13px;cursor:pointer;transition:.12s;}
  .menu-item:hover{background:rgba(165,180,252,.14);color:#fff;}
  .menu-item .mi-ic{width:20px;text-align:center;opacity:.85;}
  .menu-item .mi-r{margin-left:auto;font-family:var(--font-mono);font-size:8.5px;color:var(--muted);}
  #deck[dir="rtl"] .menu-item .mi-r{margin-left:0;margin-right:auto;}

  /* ══ WAR ROOM ══ */
  .wr-top{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:8px 0 14px;
    background:var(--surface);border:1px solid var(--edge);border-radius:16px;box-shadow:var(--shadow);padding:14px 18px;}
  .wr-title{font-family:var(--font-display);font-weight:700;font-size:clamp(20px,2.6vw,30px);letter-spacing:.14em;
    background:linear-gradient(120deg,#3ee9ff,#a5b4fc,#e0b3ff);-webkit-background-clip:text;background-clip:text;color:transparent;}
  .wr-sub{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:2px;}
  .defcon{display:flex;align-items:center;gap:10px;margin-inline-start:auto;}
  .defcon .dl{font-family:var(--font-mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);}
  .defcon .segs{display:flex;gap:4px;}
  .defcon .seg{width:26px;height:12px;border-radius:3px;background:var(--track);border:1px solid var(--edge2);}
  .defcon .lvl{font-family:var(--font-display);font-weight:700;font-size:22px;color:var(--crit);font-variant-numeric:tabular-nums;text-shadow:0 0 16px var(--crit);}
  .wr-strike{font-family:var(--font-display);font-weight:600;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#fff;
    background:linear-gradient(120deg,var(--crit),#b5179e);border:none;padding:11px 18px;border-radius:11px;cursor:pointer;box-shadow:0 6px 22px -6px var(--crit);}
  .wr-strike:hover{transform:translateY(-1px);}
  #wrTheater{position:relative;padding:0;overflow:hidden;min-height:460px;}
  #wrCanvas{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:crosshair;}
  .list{display:flex;flex-direction:column;gap:9px;overflow-y:auto;}
  .camp{background:var(--track);border:1px solid var(--edge2);border-radius:11px;padding:10px 11px;}
  .camp .cn{display:flex;justify-content:space-between;font-family:var(--font-display);font-weight:600;font-size:12px;color:var(--text);}
  .camp .ca{font-family:var(--font-mono);font-size:9px;color:var(--muted);margin:2px 0 6px;}
  .camp .cbar2{height:6px;border-radius:4px;background:var(--track);overflow:hidden;border:1px solid var(--edge2);}
  .camp .cbar2 i{display:block;height:100%;background:linear-gradient(90deg,var(--warn),var(--crit));}
  .actor{display:flex;align-items:center;gap:10px;padding:7px 4px;border-bottom:1px solid var(--edge2);}
  .actor .fl{width:26px;height:18px;border-radius:3px;flex:0 0 auto;display:grid;place-items:center;font-size:11px;background:var(--track);border:1px solid var(--edge2);}
  .actor .an{flex:1;min-width:0;font-family:var(--font-mono);font-size:11px;color:var(--text);}
  .actor .an small{color:var(--muted);}
  .actor .ap{font-family:var(--font-mono);font-size:11px;color:var(--crit);}
  .kill{display:flex;flex-direction:column;gap:6px;}
  .kstage{display:flex;align-items:center;gap:9px;font-family:var(--font-mono);font-size:11px;color:var(--muted);padding:6px 9px;border-radius:8px;border:1px solid var(--edge2);}
  .kstage .kd{width:8px;height:8px;border-radius:50%;background:var(--edge2);flex:0 0 auto;}
  .kstage.done{color:var(--text);} .kstage.done .kd{background:var(--ok);box-shadow:0 0 7px var(--ok);}
  .kstage.active{color:#fff;border-color:var(--crit);background:color-mix(in srgb,var(--crit) 12%,transparent);}
  .kstage.active .kd{background:var(--crit);box-shadow:0 0 9px var(--crit);}
  .respbtns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;}
  .respbtns button{font-family:var(--font-mono);font-size:10px;color:var(--text);background:var(--track);border:1px solid var(--edge2);border-radius:9px;padding:9px 8px;cursor:pointer;transition:.14s;}
  .respbtns button:hover{border-color:var(--a1);color:var(--a1);}
  .rb-meter{height:12px;border-radius:6px;overflow:hidden;display:flex;margin-top:8px;border:1px solid var(--edge2);}
  .rb-meter .red{background:linear-gradient(90deg,#ff6b81,#b5179e);} .rb-meter .blue{background:linear-gradient(90deg,#3ee9ff,#6366f1);}
  .rb-lab{display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:9px;margin-top:4px;}
  .rb-lab .r{color:#ff6b81;} .rb-lab .b{color:#3ee9ff;}
  .comms{font-family:var(--font-mono);font-size:11px;display:flex;flex-direction:column;gap:6px;overflow-y:auto;max-height:120px;}
  .comms .cm{color:var(--muted);} .comms .cm b{color:var(--a1);}

  ::-webkit-scrollbar{width:8px;height:8px;} ::-webkit-scrollbar-thumb{background:var(--edge2);border-radius:4px;} ::-webkit-scrollbar-track{background:transparent;}

  @media (max-width:1100px){
    .ledger{grid-template-columns:repeat(3,1fr);}
    .s3{grid-column:span 6;} .s4{grid-column:span 6;} .s6{grid-column:span 12;}
    .hero-row .card{min-height:340px;} #wrTheater{min-height:360px;}
  }
  @media (max-width:640px){
    .ledger{grid-template-columns:repeat(2,1fr);gap:9px;}
    .s3,.s4,.s6{grid-column:span 12;}
    .cbar{gap:9px 10px;}
    .brand{flex:1 1 100%;}
    .themeswitch{order:6;flex:1 1 100%;justify-content:center;}
    .pills{order:7;flex-wrap:wrap;}
    .incident-btn{order:8;flex:1 1 100%;text-align:center;}
    .search{order:9;flex:1 1 100%;max-width:100%;}
    .themeswitch button{flex:1;padding:7px 6px;font-size:10.5px;}
    .kpi .k-val{font-size:22px;}
    .launch{grid-template-columns:1fr;}
  }
  @media (prefers-reduced-motion:reduce){.pill i,#aurora::after{animation:none;}}
`;

export const CC_HTML = `<div id="deck" data-dir="nebula" dir="ltr">
  <div id="bg" aria-hidden="true"><div id="brandbg"></div><div id="veil"></div><div id="aurora"></div><div id="grain"></div><div class="warm" id="warm"></div></div>

  <div id="scrim"></div>
  <nav id="menu" aria-label="Main menu">
    <div class="menu-head"><span class="mt" data-t="menuTitle">MENU</span><button class="menu-x" id="menuClose" aria-label="Close">✕</button></div>
    <div class="launch">
      <button data-go="cockpit" class="on"><span class="li">◈</span><span data-t="cockpit">Cockpit</span><small data-t="mLaunchC">command deck</small></button>
      <button data-go="warroom"><span class="li">⚔</span><span data-t="warroom">War Room</span><small data-t="mLaunchW">live operations</small></button>
    </div>
    <div id="menuNav"></div>
  </nav>

  <div id="content">

    <!-- SHARED COMMAND BAR -->
    <div class="cbar">
      <div class="brand">
        <button class="iconbtn" id="menuBtn" aria-label="Menu"><span class="ic">☰</span><span data-t="menu">Menu</span></button>
        <button class="iconbtn" id="backBtn" aria-label="Back"><span class="ic" id="backIc">←</span><span data-t="back">Back</span></button>
        <div class="logo"><img src="/brand-cover.jpg" alt="Weissman Cybersecurity" /></div>
        <div class="wm"><b>WEISSMAN</b><span data-t="tag">Command Center</span></div>
      </div>
      <div class="search">
        <span style="color:var(--muted);font-family:var(--font-mono);font-size:12px;">⌕</span>
        <input id="cmdsearch" data-tph="search" placeholder="Search targets, engines, findings…" aria-label="Search" />
      </div>
      <div class="pills">
        <span class="pill"><i></i><span data-t="cortex">Cortex online</span></span>
        <span class="pill" id="clock">--:--:--</span>
      </div>
      <button class="incident-btn" id="incidentBtn" data-t="incident">Live incident</button>
      <button class="iconbtn" id="langBtn" aria-label="Language"><span class="ic">🌐</span><span id="langLabel">עברית</span></button>
      <div class="themeswitch" id="themeswitch">
        <button data-dir="daylight">☀ Daylight</button>
        <button data-dir="holo">◈ Holo</button>
        <button data-dir="nebula" class="on">✦ Nebula</button>
      </div>
    </div>

    <!-- ═══════════ VIEW: COCKPIT ═══════════ -->
    <section class="view on" id="view-cockpit">
      <div class="ledger" id="ledger"></div>
      <div class="grid hero-row" style="margin-bottom:14px;">
        <div class="card s3">
          <div class="ch"><div class="ht"><b data-t="cCortex">Cortex Reasoning</b><span class="rt">/cortex · live decisions</span></div><a class="open">OPEN ▸</a></div>
          <div class="cbody"><div class="stream" id="cortex"></div></div>
        </div>
        <div class="card s6" id="theater">
          <div class="plate"></div>
          <canvas id="mapCanvas" class="viz" style="display:none;"></canvas>
          <canvas id="globeCanvas" class="viz"></canvas>
          <div class="theater-hud">
            <div><div class="theater-title" id="theaterTitle" data-t="cTheater">Living Threat Globe</div><div class="theater-sub">/threat-map · 147 engines</div></div>
            <div style="text-align:right;"><div class="theater-title" id="theaterCount" style="color:var(--crit);">—</div><div class="theater-sub" data-t="activeBreaches">active breaches</div></div>
          </div>
          <div class="lockcard" id="lockcard"></div>
          <button class="warp-btn" id="warpBtn">⚡ Warp to breach</button>
        </div>
        <div class="card s3">
          <div class="ch"><div class="ht"><b data-t="cCouncil">Council · HITL</b><span class="rt">/council · approval</span></div><a class="open">OPEN ▸</a></div>
          <div class="cbody"><div class="council" id="council"></div></div>
        </div>
      </div>
      <div class="grid">
        <div class="card s12">
          <div class="ch"><div class="ht"><b data-t="cEkg">System-Pulse EKG</b><span class="rt">/pulse · platform health</span></div><span class="live-n" id="bpm">72 bpm</span></div>
          <div class="cbody vizbox" style="min-height:96px;height:96px;"><canvas id="ekgCanvas" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cEngine">Engine Room</b><span class="rt">/engines · 147 mesh</span></div><span class="live-n" id="engN">—</span></div>
          <div class="cbody vizbox"><canvas id="engineCanvas" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cHeal">Auto-Heal</b><span class="rt">/auto-heal · remediation</span></div><span class="live-n" id="mttr">MTTR 4.2m</span></div>
          <div class="cbody"><div class="timeline" id="heal"></div></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cNeural">Neural Engine Web</b><span class="rt">/neural-web · Cortex graph</span></div><span class="live-n">42 nodes</span></div>
          <div class="cbody vizbox"><canvas id="neuralCanvas" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cDeception">Deception Grid</b><span class="rt">/deception · live decoys</span></div><span class="live-n" id="decoyN">—</span></div>
          <div class="cbody"><div class="heatgrid" id="deception" style="grid-template-columns:repeat(12,1fr);"></div></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cSwarm">Swarm-Mind</b><span class="rt">/swarm-mind · consensus</span></div><span class="live-n" id="swarmN">consensus 0.0</span></div>
          <div class="cbody vizbox"><canvas id="swarmCanvas" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cIdentity">Identity Matrix</b><span class="rt">/identity-matrix · privilege heat</span></div><span class="live-n" id="idN">—</span></div>
          <div class="cbody"><div class="heatgrid" id="identity" style="grid-template-columns:repeat(16,1fr);"></div></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cAirisk">AI-Model-Risk</b><span class="rt">/ai-model-risk · drift</span></div><span class="live-n" id="airisk">low</span></div>
          <div class="cbody radarwrap"><svg id="radar" width="220" height="180" viewBox="0 0 220 180"></svg></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cEdge">Global Edge Swarm</b><span class="rt">/edge-swarm · regional</span></div><span class="live-n" id="edgeN">—</span></div>
          <div class="cbody vizbox"><canvas id="edgeCanvas" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="cMc">CEO Mission Control</b><span class="rt">/mission-control · board-ready</span></div><a class="open">OPEN ▸</a></div>
          <div class="cbody"><div class="mc"><div class="grade"><span class="g" id="mcgrade">A−</span><span class="gd"><span data-t="posture">Global posture</span><br/><span data-t="risk">Risk</span> <b id="mcrisk" style="color:var(--text)">38</b>/100 · ▼12</span></div><div class="risks" id="mcrisks"></div></div></div>
        </div>
        <div class="card s12">
          <div class="ch"><div class="ht"><b data-t="cFindings">Live Findings Pipeline</b><span class="rt">/findings · streaming + auto-containment</span></div><span class="live-n" id="findN">—</span></div>
          <div class="cbody" style="padding:0;max-height:280px;overflow-y:auto;">
            <table class="ftable"><thead><tr><th data-t="thSev">Sev</th><th data-t="thTarget">Target</th><th>CVE</th><th>MITRE</th><th data-t="thEngine">Engine</th><th data-t="thVector">Vector</th><th data-t="thStatus">Status</th></tr></thead><tbody id="findings"></tbody></table>
          </div>
        </div>
      </div>
      <div class="footnote"><span data-t="foot">Cockpit replacement · every card folds a cockpit module into a menu route</span> · <b data-t="footb">zero black by design</b></div>
    </section>

    <!-- ═══════════ VIEW: WAR ROOM ═══════════ -->
    <section class="view" id="view-warroom">
      <div class="wr-top">
        <div><div class="wr-title" data-t="wrTitle">WAR ROOM</div><div class="wr-sub" data-t="wrSub">live global operations · autonomous + human-in-the-loop</div></div>
        <div class="defcon">
          <div><div class="dl" data-t="wrDefcon">Threat Level</div><div class="segs" id="defconSegs"></div></div>
          <div class="lvl" id="defconLvl">3</div>
        </div>
        <button class="wr-strike" id="wrStrikeBtn" data-t="wrStrike">Launch response</button>
      </div>
      <div class="grid">
        <div class="card s3">
          <div class="ch"><div class="ht"><b data-t="wrCampaigns">Active Campaigns</b><span class="rt">/campaigns · tracked</span></div><span class="live-n" id="campN">—</span></div>
          <div class="cbody"><div class="list" id="wrCampaigns" style="max-height:210px;"></div></div>
          <div class="ch" style="border-top:1px solid var(--edge2);"><div class="ht"><b data-t="wrActors">Threat Actors</b><span class="rt">attribution</span></div></div>
          <div class="cbody"><div class="list" id="wrActors"></div></div>
        </div>
        <div class="card s6" id="wrTheater">
          <canvas id="wrCanvas" class="viz"></canvas>
          <div class="theater-hud">
            <div><div class="theater-title" data-t="wrTheaterT">Battle Theater</div><div class="theater-sub">/threat-map · converging attack vectors</div></div>
            <div style="text-align:right;"><div class="theater-title" id="wrCount" style="color:var(--crit);">—</div><div class="theater-sub" data-t="incoming">incoming vectors</div></div>
          </div>
        </div>
        <div class="card s3">
          <div class="ch"><div class="ht"><b data-t="wrKill">Kill-Chain</b><span class="rt">current adversary stage</span></div></div>
          <div class="cbody"><div class="kill" id="wrKill"></div></div>
          <div class="ch" style="border-top:1px solid var(--edge2);"><div class="ht"><b data-t="wrResponse">Response Console</b><span class="rt">HITL actions</span></div></div>
          <div class="cbody">
            <div class="respbtns">
              <button data-t="rIsolate">Isolate host</button><button data-t="rRevoke">Revoke sessions</button>
              <button data-t="rBlock">Block egress</button><button data-t="rDeploy">Deploy decoy</button>
            </div>
            <div class="rb-meter"><div class="red" id="rbRed" style="width:38%"></div><div class="blue" id="rbBlue" style="width:62%"></div></div>
            <div class="rb-lab"><span class="r" data-t="wrRed">Red team</span><span class="b" data-t="wrBlue">Blue containment</span></div>
          </div>
        </div>
        <div class="card s8">
          <div class="ch"><div class="ht"><b data-t="wrPulse">Battle Pulse</b><span class="rt">/pulse · operational tempo</span></div><span class="live-n" id="wrBpm">88 bpm</span></div>
          <div class="cbody vizbox" style="min-height:90px;height:90px;"><canvas id="wrEkg" class="viz"></canvas></div>
        </div>
        <div class="card s4">
          <div class="ch"><div class="ht"><b data-t="wrComms">Command Stream</b><span class="rt">decisions · comms</span></div></div>
          <div class="cbody"><div class="comms" id="wrComms"></div></div>
        </div>
      </div>
      <div class="footnote"><b data-t="wrFoot">World-class war room</b> <span data-t="wrFoot2">· cinematic, actionable, never-black — draft for your direction</span></div>
    </section>

  </div>
</div>`;

export function mountCommandCenter(root, THREE, opts) {
  opts = opts || {};
  var _timers = [], _win = [], disposed = false;
  function IV(fn, ms) { var id = setInterval(fn, ms); _timers.push(id); return id; }
  function addWin(ev, fn, o) { window.addEventListener(ev, fn, o); _win.push([ev, fn, o]); }

  
  var R=matchMedia('(prefers-reduced-motion: reduce)').matches;
  var rnd=function(n){return (Math.random()*n)|0;}, pick=function(a){return a[rnd(a.length)];};
  var deck=document.getElementById('deck');

  /* ─── i18n ─── */
  var LANG='en';
  var T={
    tag:['Command Center','מרכז שליטה'], menu:['Menu','תפריט'], back:['Back','חזור'],
    menuTitle:['MENU','תפריט'], cortex:['Cortex online','Cortex מחובר'],
    incident:['Live incident','אירוע חי'], search:['Search targets, engines, findings…','חיפוש יעדים, מנועים, ממצאים…'],
    cockpit:['Cockpit','קוקפיט'], warroom:['War Room','חדר מלחמה'],
    mLaunchC:['command deck','לוח פיקוד'], mLaunchW:['live operations','מבצעים חיים'],
    cCortex:['Cortex Reasoning','חשיבת Cortex'], cTheater:['Living Threat Globe','גלוב איומים חי'],
    cCouncil:['Council · HITL','מועצה · HITL'], cEkg:['System-Pulse EKG','דופק מערכת'],
    cEngine:['Engine Room','חדר מנועים'], cHeal:['Auto-Heal','ריפוי אוטומטי'],
    cNeural:['Neural Engine Web','רשת עצבית'], cDeception:['Deception Grid','רשת הונאה'],
    cSwarm:['Swarm-Mind','תודעת נחיל'], cIdentity:['Identity Matrix','מטריצת זהויות'],
    cAirisk:['AI-Model-Risk','סיכון מודל AI'], cEdge:['Global Edge Swarm','נחיל קצה גלובלי'],
    cMc:['CEO Mission Control','בקרת משימות'], cFindings:['Live Findings Pipeline','צנרת ממצאים חיה'],
    activeBreaches:['active breaches','פירצות פעילות'], posture:['Global posture','מצב גלובלי'], risk:['Risk','סיכון'],
    thSev:['Sev','חומרה'], thTarget:['Target','יעד'], thEngine:['Engine','מנוע'], thVector:['Vector','וקטור'], thStatus:['Status','סטטוס'],
    foot:['Cockpit replacement · every card folds a cockpit module into a menu route','תחליף לקוקפיט · כל כרטיס מקפל מודול לתפריט'],
    footb:['zero black by design','אפס שחור בעיצוב'],
    kEngines:['Engines Live','מנועים פעילים'], kThreats:['Active Threats','איומים פעילים'],
    kContained:['Auto-Contained','נוטרלו אוטו׳'], kMttc:['Mean Time-to-Contain','זמן בלימה'],
    kCouncil:['Council Queue','תור מועצה'], kEdge:['Edge Nodes','צמתי קצה'],
    warp:['Warp to breach','טוס לפירצה'],
    /* war room */
    wrTitle:['WAR ROOM','חדר מלחמה'], wrSub:['live global operations · autonomous + human-in-the-loop','מבצעים גלובליים חיים · אוטונומי + אדם בלולאה'],
    wrDefcon:['Threat Level','רמת איום'], wrStrike:['Launch response','שגר תגובה'],
    wrCampaigns:['Active Campaigns','מבצעים פעילים'], wrActors:['Threat Actors','גורמי איום'],
    wrKill:['Kill-Chain','שרשרת המתה'], wrResponse:['Response Console','קונסולת תגובה'],
    wrTheaterT:['Battle Theater','זירת קרב'], incoming:['incoming vectors','וקטורים נכנסים'],
    wrPulse:['Battle Pulse','דופק קרב'], wrComms:['Command Stream','זרם פיקוד'],
    wrRed:['Red team','צוות אדום'], wrBlue:['Blue containment','בלימה כחולה'],
    rIsolate:['Isolate host','בודד מארח'], rRevoke:['Revoke sessions','בטל הרשאות'], rBlock:['Block egress','חסום יציאה'], rDeploy:['Deploy decoy','פרוס פיתיון'],
    wrFoot:['World-class war room','חדר מלחמה עולמי'], wrFoot2:['· cinematic, actionable, never-black — draft for your direction','· קולנועי, אקטיבי, ללא שחור — טיוטה לכיוונך'],
    navGroups:['Navigate','ניווט']
  };
  function t(k){var e=T[k];return e?e[LANG==='he'?1:0]:k;}
  function applyLang(l){
    LANG=l; deck.setAttribute('dir', l==='he'?'rtl':'ltr');
    document.querySelectorAll('[data-t]').forEach(function(el){el.textContent=t(el.getAttribute('data-t'));});
    document.querySelectorAll('[data-tph]').forEach(function(el){el.setAttribute('placeholder',t(el.getAttribute('data-tph')));});
    document.getElementById('langLabel').textContent = l==='he'?'EN':'עברית';
    if(document.getElementById('warpBtn')) document.getElementById('warpBtn').firstChild.nodeValue='⚡ ';
    document.getElementById('warpBtn').lastChild.nodeValue=t('warp');
    buildMenuNav();
  }

  /* ─── domain vocab ─── */
  var CITIES=[['New York',40.71,-74.0],['London',51.5,-0.12],['Tel Aviv',32.08,34.78],['Moscow',55.75,37.62],
    ['Beijing',39.9,116.4],['Tokyo',35.68,139.7],['Singapore',1.35,103.8],['Sydney',-33.87,151.2],
    ['São Paulo',-23.55,-46.63],['Frankfurt',50.11,8.68],['Dubai',25.2,55.27],['Mumbai',19.08,72.88],
    ['San Francisco',37.77,-122.42],['Toronto',43.65,-79.38],['Lagos',6.52,3.38],['Seoul',37.57,127.0],
    ['Amsterdam',52.37,4.9],['Paris',48.86,2.35],['Los Angeles',34.05,-118.24],['Istanbul',41.0,28.98],
    ['Kyiv',50.45,30.52],['Bangkok',13.75,100.5],['Jakarta',-6.2,106.8],['Hong Kong',22.32,114.17]];
  var CVES=['CVE-2024-38112','CVE-2025-0282','CVE-2024-3400','CVE-2025-21298','CVE-2024-49113','CVE-2025-24085','CVE-2024-9680','CVE-2025-0411'];
  var MITRE=['T1078','T1550','T1190','T1210','T1557','T1021','T1567','T1499','T1110','T1213'];
  var VECTORS=['Kerberoast → DA','SAML golden ticket','Exposed S3 IMDSv1','GraphQL introspection','HTTP smuggling','JWT alg=none','CI/CD token exfil','WebSocket hijack','Password spray','Cache deception'];
  var ENGINES=['PQC Radar','ITDR Core','CASB / DLP','Kerberos Recon','SAML Forge','Kill-Chain Orch','Dark-Web Monitor','OAST Callback','Digital Twin','Cortex Bridge','Nexus Swarm','Attack-Surface','Cloud Posture','Supply-Chain','UEBA Anomaly','Deception Grid','Neural Web','Auto-Heal'];
  var COMPANIES=['acme-corp.com','northwind.io','globex.net','initech.co','umbrella.med','stark-ind.com','wayne-ent.org','cyberdyne.ai','tyrell.io','hooli.xyz','piedpiper.net'];
  var breaches=[];
  for(var i=0;i<12;i++){var c=CITIES[i%CITIES.length];
    breaches.push({id:i,name:c[0],lat:c[1],lon:c[2],domain:pick(COMPANIES),cve:pick(CVES),vector:pick(VECTORS),engine:pick(ENGINES),mitre:pick(MITRE),sev:i<3?'c':(i<7?'h':'m'),score:70+rnd(30)});}

  /* ─── clock ─── */
  var clockEl=document.getElementById('clock');
  (function tk(){if(disposed)return;clockEl.textContent=new Date().toISOString().slice(11,19)+'Z';setTimeout(tk,1000);})();

  /* ─── theme ─── */
  var dir='nebula';
  var titleKeyByDir={daylight:'cTheater',holo:'cTheater',nebula:'cTheater'};
  document.getElementById('themeswitch').addEventListener('click',function(e){
    var b=e.target.closest('button'); if(!b)return; var d=b.getAttribute('data-dir'); if(d===dir)return;
    [].forEach.call(this.children,function(x){x.classList.toggle('on',x===b);});
    dir=d; deck.setAttribute('data-dir',d);
    var useGlobe=(d==='nebula');
    document.getElementById('globeCanvas').style.display=useGlobe?'block':'none';
    document.getElementById('mapCanvas').style.display=useGlobe?'none':'block';
    if(useGlobe&&!globeReady) initGlobe();
    setTimeout(resizeAll,30);
  });

  /* ─── KPI ledger ─── */
  var KPIS=[['kEngines','147',''],['kThreats','12','var(--crit)'],['kContained','1,284',''],['kMttc','4.2m',''],['kCouncil','3',''],['kEdge','86','']];
  var ledger=document.getElementById('ledger');
  function spark(){var p=[],y=12;for(var i=0;i<14;i++){y+=(Math.random()-.5)*7;y=Math.max(3,Math.min(21,y));p.push([(i/13)*56,y]);}
    return '<svg width="56" height="24"><path d="M'+p.map(function(q){return q[0].toFixed(1)+','+q[1].toFixed(1);}).join(' L')+'" fill="none" stroke="var(--a1)" stroke-width="1.5" opacity="0.85"/><circle cx="'+p[13][0].toFixed(1)+'" cy="'+p[13][1].toFixed(1)+'" r="2.2" fill="var(--a2)"/></svg>';}
  KPIS.forEach(function(k){var d=document.createElement('div');d.className='kpi';
    d.innerHTML='<div class="k-lab" data-t="'+k[0]+'">'+t(k[0])+'</div><div class="k-val" style="color:'+(k[1],k[2]||'var(--text)')+'">'+k[1]+'</div><div class="k-delta" style="color:var(--ok)">▲ live</div>'+spark();ledger.appendChild(d);});
  var contained=1284;
  IV(function(){contained+=rnd(3);var v=ledger.querySelectorAll('.k-val');if(v[2])v[2].textContent=contained.toLocaleString();if(v[1])v[1].textContent=breaches.length;},2600);

  /* ─── Cortex stream ─── */
  var cortexEl=document.getElementById('cortex');
  function cortexMsg(esc){var b=pick(breaches);
    var norm=['Correlated <b>'+b.domain+'</b> across '+pick(ENGINES)+' + UEBA — one campaign',
      'Simulated <b>'+b.vector+'</b> in Digital Twin — blast radius 3 hosts',
      'Confidence rising on <b>'+b.name+'</b> · '+b.cve+' · staging containment',
      'Dark-Web match for <b>'+pick(COMPANIES)+'</b> creds — rotating + MFA'];
    return {esc:!!esc,txt:esc?'ESCALATE · <b>'+b.domain+'</b> · '+b.vector+' confirmed — routing to Council':pick(norm),conf:esc?96:(70+rnd(26))};}
  function pushCortex(esc){var m=cortexMsg(esc);var d=document.createElement('div');d.className='cx'+(m.esc?' esc':'');
    d.innerHTML='<div class="cxh"><span>'+(m.esc?'⚠ decision':'reasoning')+'</span><span>'+new Date().toISOString().slice(11,19)+'</span></div><div class="cxm">'+m.txt+'</div><div class="conf"><i style="width:'+m.conf+'%"></i></div>';
    cortexEl.insertBefore(d,cortexEl.firstChild);while(cortexEl.children.length>18)cortexEl.removeChild(cortexEl.lastChild);}
  for(var q=0;q<7;q++)pushCortex(false);
  IV(function(){pushCortex(false);},3000);

  /* ─── Council ─── */
  var councilEl=document.getElementById('council'),councilItems=[];
  function renderCouncil(){councilEl.innerHTML='';councilItems.forEach(function(it){var d=document.createElement('div');d.className='cc';
    d.innerHTML='<div class="ccring" style="--p:'+it.p+'%"><b>'+Math.ceil((100-it.p)/10)+'</b></div><div class="ccm"><div class="t">'+it.act+'</div><div class="s">'+it.tgt+'</div></div><div class="act"><button class="ok">✓</button><button>hold</button></div>';councilEl.appendChild(d);});}
  var C_ACTS=['Isolate host','Revoke session','Rotate keys','Block egress','Quarantine asset'];
  for(var w=0;w<3;w++)councilItems.push({act:pick(C_ACTS),tgt:pick(COMPANIES),p:20+rnd(60)});
  renderCouncil();
  IV(function(){councilItems.forEach(function(it){it.p=Math.min(100,it.p+2+rnd(3));});councilItems=councilItems.filter(function(it){return it.p<100;});while(councilItems.length<3)councilItems.push({act:pick(C_ACTS),tgt:pick(COMPANIES),p:15+rnd(40)});renderCouncil();},1400);

  /* ─── Auto-Heal ─── */
  var healEl=document.getElementById('heal');
  function pushHeal(){var d=document.createElement('div');d.className='heal';
    d.innerHTML='<span class="hs" style="background:var(--ok);box-shadow:0 0 7px var(--ok)"></span><span class="ht2">'+pick(['Isolated','Rotated','Patched','Contained','Quarantined'])+' · '+pick(COMPANIES)+'</span><span class="hd">'+(1.2+Math.random()*6).toFixed(1)+'s</span>';
    healEl.insertBefore(d,healEl.firstChild);while(healEl.children.length>10)healEl.removeChild(healEl.lastChild);}
  for(var h=0;h<6;h++)pushHeal(); IV(pushHeal,2200);

  /* ─── heat grids ─── */
  function buildHeat(el,n){el.innerHTML='';var cells=[];for(var i=0;i<n;i++){var c=document.createElement('div');c.className='heatcell';el.appendChild(c);cells.push(c);}return cells;}
  var decoyCells=buildHeat(document.getElementById('deception'),72),idCells=buildHeat(document.getElementById('identity'),80);
  var decoyN=document.getElementById('decoyN'),idN=document.getElementById('idN');
  function pulseHeat(cells,color,cnt){for(var i=0;i<cnt;i++){var c=pick(cells);c.style.background=color;c.style.boxShadow='0 0 8px '+color;(function(cc){setTimeout(function(){cc.style.background='var(--track)';cc.style.boxShadow='none';},900+rnd(900));})(c);}}
  IV(function(){var tt=rnd(4);pulseHeat(decoyCells,'var(--a3)',tt);decoyN.textContent=(41+rnd(20))+' lures · '+tt;},1500);
  IV(function(){pulseHeat(idCells,rnd(5)?'var(--a1)':'var(--crit)',2+rnd(3));idN.textContent=(1200+rnd(80))+' ids';},1300);

  /* ─── AI radar ─── */
  var radar=document.getElementById('radar'),rlabels=['Inject','Drift','Exfil','Jailbreak','Poison','Leak'];
  function drawRadar(){var cx=110,cy=90,rad=62,n=6,f='';
    for(var ring=1;ring<=3;ring++){var pp=[];for(var i=0;i<n;i++){var a=-Math.PI/2+i/n*2*Math.PI;pp.push((cx+Math.cos(a)*rad*ring/3).toFixed(1)+','+(cy+Math.sin(a)*rad*ring/3).toFixed(1));}f+='<polygon points="'+pp.join(' ')+'" fill="none" stroke="var(--hairline)" stroke-width="1"/>';}
    var poly=[],vals=[];for(var i=0;i<n;i++){var v=.25+Math.random()*.6;vals.push(v);var a=-Math.PI/2+i/n*2*Math.PI;poly.push((cx+Math.cos(a)*rad*v).toFixed(1)+','+(cy+Math.sin(a)*rad*v).toFixed(1));f+='<text x="'+(cx+Math.cos(a)*(rad+13)).toFixed(1)+'" y="'+(cy+Math.sin(a)*(rad+13)+3).toFixed(1)+'" font-size="8" fill="var(--muted)" text-anchor="middle">'+rlabels[i]+'</text>';}
    f+='<polygon points="'+poly.join(' ')+'" fill="color-mix(in srgb,var(--a2) 24%,transparent)" stroke="var(--a2)" stroke-width="1.5"/>';
    radar.innerHTML=f;var mx=Math.max.apply(null,vals);var el=document.getElementById('airisk');el.textContent=mx>.7?'elevated':(mx>.5?'guarded':'low');el.style.color=mx>.7?'var(--warn)':'var(--ok)';}
  drawRadar();IV(drawRadar,2600);

  /* ─── mission control ─── */
  var mcr=document.getElementById('mcrisks');
  [['Exposed IMDSv1 on cloud edge','HIGH'],['Kerberos delegation drift','HIGH'],['3 SaaS tokens un-rotated','MED']].forEach(function(r){var d=document.createElement('div');d.className='rk';d.innerHTML='<span>'+r[0]+'</span><span>'+r[1]+'</span>';mcr.appendChild(d);});

  /* ─── findings ─── */
  var findEl=document.getElementById('findings'),findN=document.getElementById('findN'),findCount=0;
  function sevCls(s){return s==='c'?'c':s==='h'?'h':s==='m'?'m':'l';}
  function pushFinding(b,flash){b=b||pick(breaches);findCount++;var tr=document.createElement('tr');if(flash)tr.className='flash';
    var st=Math.random()>.4?'<span class="status-ok">contained</span>':'<span class="status-run">running</span>';
    tr.innerHTML='<td><span class="sev '+sevCls(b.sev)+'"><i></i></span></td><td class="tgt">'+b.domain+'</td><td>'+b.cve+'</td><td><span class="tag">'+b.mitre+'</span></td><td>'+b.engine+'</td><td>'+b.vector+'</td><td>'+st+'</td>';
    findEl.insertBefore(tr,findEl.firstChild);while(findEl.children.length>40)findEl.removeChild(findEl.lastChild);findN.textContent=findCount+' today';}
  for(var f2=0;f2<9;f2++)pushFinding(pick(breaches),false);
  IV(function(){pushFinding(pick(breaches),false);},2400);

  /* ══ canvas helpers ══ */
  function fit(cv){var r=cv.getBoundingClientRect();var dpr=Math.min(2,window.devicePixelRatio||1);cv.width=Math.max(1,r.width*dpr);cv.height=Math.max(1,r.height*dpr);var x=cv.getContext('2d');x.setTransform(dpr,0,0,dpr,0,0);return {w:r.width,h:r.height,x:x};}
  var LAND=[[48,-100,22,32],[15,-90,10,12],[-15,-60,26,17],[52,12,15,26],[2,20,33,24],[28,45,12,15],[62,90,16,68],[30,78,17,20],[10,105,15,17],[40,112,16,18],[-25,133,15,22],[72,-40,10,22],[36,-6,7,9],[60,-150,10,18]];
  function isLand(lat,lon){for(var i=0;i<LAND.length;i++){var L=LAND[i];var dl=((lon-L[1]+540)%360)-180;var a=(lat-L[0])/L[2],b=dl/L[3];if(a*a+b*b<=1)return true;}return false;}
  var cssCache={},cssDir='';
  function cssv(name){if(cssDir!==dir){cssCache={};cssDir=dir;}if(cssCache[name])return cssCache[name];var v=getComputedStyle(deck).getPropertyValue(name).trim()||'#6366f1';cssCache[name]=v;return v;}

  /* flat map (daylight/holo) */
  var mapCv=document.getElementById('mapCanvas'),mapDots=null;
  function mapProj(lat,lon,w,h){return [(lon+180)/360*w,(90-lat)/180*h];}
  function genDots(w,h){var d=[];for(var i=0;i<1500;i++){var lat=90-Math.acos(2*Math.random()-1)*180/Math.PI,lon=Math.random()*360-180;if(isLand(lat,lon)){d.push(mapProj(lat,lon,w,h));}}return d;}
  var mapArcs=[];for(var i=0;i<8;i++){mapArcs.push({a:pick(breaches),b:pick(CITIES),t:Math.random(),spd:.004+Math.random()*.004});}
  var lockTarget=null,lockAnim=0;
  function arcCol(s,a){return 'rgba('+(s==='c'?'255,107,129':'62,233,255')+','+a+')';}
  function drawMap(){var g=fit(mapCv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);
    if(!mapDots||mapDots._w!==w){mapDots=genDots(w,h);mapDots._w=w;}
    x.strokeStyle=cssv('--map-grid');x.lineWidth=1;for(var gx=0;gx<=w;gx+=w/8){x.beginPath();x.moveTo(gx,0);x.lineTo(gx,h);x.stroke();}for(var gy=0;gy<=h;gy+=h/5){x.beginPath();x.moveTo(0,gy);x.lineTo(w,gy);x.stroke();}
    x.fillStyle=cssv('--map-land');for(var i=0;i<mapDots.length;i++)x.fillRect(mapDots[i][0],mapDots[i][1],1.3,1.3);
    var now=performance.now();
    mapArcs.forEach(function(ar){var pa=mapProj(ar.a.lat,ar.a.lon,w,h),pb=mapProj(ar.b[1],ar.b[2],w,h);var mx=(pa[0]+pb[0])/2,my=(pa[1]+pb[1])/2-Math.abs(pa[0]-pb[0])*.18;
      x.strokeStyle=arcCol(ar.a.sev,.5);x.lineWidth=1.4;x.beginPath();x.moveTo(pa[0],pa[1]);x.quadraticCurveTo(mx,my,pb[0],pb[1]);x.stroke();
      if(!R){ar.t+=ar.spd;if(ar.t>1)ar.t=0;}var tt=ar.t,ix=(1-tt)*(1-tt)*pa[0]+2*(1-tt)*tt*mx+tt*tt*pb[0],iy=(1-tt)*(1-tt)*pa[1]+2*(1-tt)*tt*my+tt*tt*pb[1];
      x.fillStyle=arcCol(ar.a.sev,1);x.shadowColor=arcCol(ar.a.sev,1);x.shadowBlur=8;x.beginPath();x.arc(ix,iy,2.4,0,7);x.fill();x.shadowBlur=0;});
    breaches.forEach(function(b){var p=mapProj(b.lat,b.lon,w,h);var col=b.sev==='c'?cssv('--crit'):b.sev==='h'?cssv('--warn'):cssv('--map-lit');var pr=2.6+Math.sin(now*.004+b.id)*1.1;
      x.fillStyle=col;x.shadowColor=col;x.shadowBlur=10;x.beginPath();x.arc(p[0],p[1],pr,0,7);x.fill();x.shadowBlur=0;x.strokeStyle=col;x.globalAlpha=.4;x.beginPath();x.arc(p[0],p[1],pr+5+Math.sin(now*.003+b.id)*3,0,7);x.stroke();x.globalAlpha=1;b._mx=p[0];b._my=p[1];});
    if(lockTarget&&lockTarget._mx){lockAnim=Math.min(1,lockAnim+.05);var lx=lockTarget._mx,ly=lockTarget._my,rr=30-lockAnim*16;x.strokeStyle=cssv('--a1');x.lineWidth=1.5;x.globalAlpha=lockAnim;x.beginPath();x.arc(lx,ly,rr,0,7);x.stroke();x.beginPath();x.moveTo(lx-rr-8,ly);x.lineTo(lx-rr+4,ly);x.moveTo(lx+rr-4,ly);x.lineTo(lx+rr+8,ly);x.moveTo(lx,ly-rr-8);x.lineTo(lx,ly-rr+4);x.moveTo(lx,ly+rr-4);x.lineTo(lx,ly+rr+8);x.stroke();x.globalAlpha=1;}}

  /* EKG (generic) */
  var ekgData=[],ekgBeat=0,ekgAmp=1;
  function ekgWave(b){var p=b%64;if(p===8)return .12;if(p===10)return -.3;if(p===12)return 1.0*ekgAmp;if(p===14)return -.45;if(p===16)return .08;return Math.sin(b*.13)*.04;}
  function drawEkgOn(cv,adv){var g=fit(cv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);
    if(adv&&!R){ekgData.push(ekgWave(ekgBeat));ekgBeat++;}else if(ekgData.length===0){for(var i=0;i<w;i++)ekgData.push(ekgWave(i));}
    while(ekgData.length>Math.max(w,320))ekgData.shift();var off=Math.max(0,ekgData.length-w);
    x.strokeStyle=cssv('--ok');x.lineWidth=1.8;x.shadowColor=cssv('--ok');x.shadowBlur=6;x.beginPath();
    for(var i=0;i<Math.min(w,ekgData.length);i++){var y=h/2-ekgData[off+i]*h*.4;i===0?x.moveTo(i,y):x.lineTo(i,y);}x.stroke();x.shadowBlur=0;ekgAmp+=(1-ekgAmp)*.02;}

  /* engine room */
  var engCv=document.getElementById('engineCanvas'),engHeat=[];for(var e=0;e<147;e++)engHeat.push(Math.random()*.5);
  var engN=document.getElementById('engN');
  function heatColor(v){if(v<.55)return 'rgba(62,233,255,'+(0.4+v*0.6)+')';if(v<.85)return 'rgba(252,211,77,'+(0.55+(v-.55)*1.2)+')';return 'rgba(255,107,129,0.95)';}
  function rr2(x,px,py,w,h,r){x.beginPath();x.moveTo(px+r,py);x.arcTo(px+w,py,px+w,py+h,r);x.arcTo(px+w,py+h,px,py+h,r);x.arcTo(px,py+h,px,py,r);x.arcTo(px,py,px+w,py,r);x.closePath();}
  function drawEngine(){var g=fit(engCv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);var cols=21,rows=7,gap=2,cw=(w-(cols-1)*gap)/cols,chh=(h-(rows-1)*gap)/rows,on=0;
    for(var i=0;i<147;i++){var r=(i/cols)|0,c=i%cols;engHeat[i]+=(Math.random()-.5)*.06;engHeat[i]=Math.max(.05,Math.min(1,engHeat[i]));var v=engHeat[i];if(v<.85)on++;x.fillStyle=heatColor(v);rr2(x,c*(cw+gap),r*(chh+gap),cw,chh,2);x.fill();}engN.textContent=on+'/147 online';}

  /* neural */
  var neuCv=document.getElementById('neuralCanvas'),neuNodes=[],neuLinks=[],neuInit=false;
  function buildNeural(w,h){neuNodes=[];neuLinks=[];neuNodes.push({x:w/2,y:h/2,r:11,core:true});var N=13;for(var i=0;i<N;i++){var a=i/N*Math.PI*2;var rad=Math.min(w,h)*(i%2?.36:.26);neuNodes.push({x:0,y:0,r:4.5,base:a,rad:rad,t:(i%5===0)});}for(var i=1;i<neuNodes.length;i++){neuLinks.push({a:0,b:i,p:Math.random()});if(i>2&&Math.random()>.5)neuLinks.push({a:1+rnd(neuNodes.length-2),b:i,p:Math.random()});}neuInit=true;}
  function drawNeural(){var g=fit(neuCv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);if(!neuInit||neuNodes._w!==w){buildNeural(w,h);neuNodes._w=w;}var now=performance.now();
    for(var i=1;i<neuNodes.length;i++){var n=neuNodes[i];var a=n.base+(R?0:now*.00007);n.x=w/2+Math.cos(a)*n.rad;n.y=h/2+Math.sin(a)*n.rad*.82;}
    neuLinks.forEach(function(l){var A=neuNodes[l.a],B=neuNodes[l.b];x.strokeStyle='color-mix(in srgb,var(--a2) 24%,transparent)';x.lineWidth=1;x.beginPath();x.moveTo(A.x,A.y);x.lineTo(B.x,B.y);x.stroke();if(!R){l.p+=.008;if(l.p>1)l.p=0;}var px=A.x+(B.x-A.x)*l.p,py=A.y+(B.y-A.y)*l.p;x.fillStyle=cssv(B.t?'--a3':'--a1');x.beginPath();x.arc(px,py,1.8,0,7);x.fill();});
    neuNodes.forEach(function(n){var c=n.core?cssv('--a3'):(n.t?cssv('--warn'):cssv('--a1'));x.fillStyle=c;x.shadowColor=c;x.shadowBlur=n.core?16:8;x.beginPath();x.arc(n.x,n.y,n.r,0,7);x.fill();x.shadowBlur=0;});}

  /* swarm */
  var swCv=document.getElementById('swarmCanvas'),swP=[],swInit=false,swTarget={x:0,y:0},swN=document.getElementById('swarmN');
  function drawSwarm(){var g=fit(swCv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);if(!swInit||swP._w!==w){swP=[];for(var i=0;i<60;i++)swP.push({x:Math.random()*w,y:Math.random()*h,vx:0,vy:0});swP._w=w;swInit=true;swTarget={x:w/2,y:h/2};}
    if(!R&&Math.random()<.01)swTarget={x:w*.3+Math.random()*w*.4,y:h*.3+Math.random()*h*.4};var conv=0;
    swP.forEach(function(p){if(!R){var dx=swTarget.x-p.x,dy=swTarget.y-p.y;p.vx=(p.vx+dx*.002)*.94;p.vy=(p.vy+dy*.002)*.94;p.x+=p.vx;p.y+=p.vy;}if(Math.hypot(swTarget.x-p.x,swTarget.y-p.y)<40)conv++;x.fillStyle='color-mix(in srgb,var(--a1) 78%,transparent)';x.beginPath();x.arc(p.x,p.y,1.7,0,7);x.fill();});
    x.strokeStyle=cssv('--a3');x.globalAlpha=.6;x.beginPath();x.arc(swTarget.x,swTarget.y,40,0,7);x.stroke();x.globalAlpha=1;swN.textContent='consensus '+(conv/60).toFixed(2);}

  /* edge */
  var edgeCv=document.getElementById('edgeCanvas'),edgeN=document.getElementById('edgeN');
  function drawEdge(){var g=fit(edgeCv),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);var cx=w/2,cy=h/2,rad=Math.min(w,h)*.34,now=performance.now(),n=14,on=0;
    x.strokeStyle=cssv('--hairline');x.beginPath();x.arc(cx,cy,rad,0,7);x.stroke();x.fillStyle=cssv('--a2');x.shadowColor=cssv('--a2');x.shadowBlur=14;x.beginPath();x.arc(cx,cy,6,0,7);x.fill();x.shadowBlur=0;
    for(var i=0;i<n;i++){var a=i/n*Math.PI*2+now*.0002;var ex=cx+Math.cos(a)*rad,ey=cy+Math.sin(a)*rad*.85;var live=Math.sin(now*.002+i)>-.6;if(live)on++;var c=live?cssv('--a1'):cssv('--muted');x.strokeStyle='color-mix(in srgb,var(--a1) 20%,transparent)';x.lineWidth=1;
      if(!R){var pk=(now*.0004+i/n)%1;x.fillStyle=c;x.globalAlpha=.5;x.beginPath();x.arc(cx+(ex-cx)*pk,cy+(ey-cy)*pk,1.5,0,7);x.fill();x.globalAlpha=1;}x.beginPath();x.moveTo(cx,cy);x.lineTo(ex,ey);x.stroke();x.fillStyle=c;x.shadowColor=c;x.shadowBlur=live?8:0;x.beginPath();x.arc(ex,ey,3.4,0,7);x.fill();x.shadowBlur=0;}edgeN.textContent=on+'/'+n+' regions';}

  /* ══ three.js glass globe ══ */
  var globeReady=false,gScene,gCam,gRend,gGlobe,gCanvas=document.getElementById('globeCanvas'),gWarp=null,gAuto=true,gQuatT=null,gArcs=[];
  function vLL(lat,lon,r){var phi=(90-lat)*Math.PI/180,th=(lon+180)*Math.PI/180;return new THREE.Vector3(-(r*Math.sin(phi)*Math.cos(th)),r*Math.cos(phi),r*Math.sin(phi)*Math.sin(th));}
  function disc(c){var cv=document.createElement('canvas');cv.width=cv.height=64;var x=cv.getContext('2d');var g=x.createRadialGradient(32,32,0,32,32,32);g.addColorStop(0,c);g.addColorStop(.4,c);g.addColorStop(1,'rgba(255,255,255,0)');x.fillStyle=g;x.beginPath();x.arc(32,32,32,0,7);x.fill();var t2=new THREE.Texture(cv);t2.needsUpdate=true;return t2;}
  function initGlobe(){if(globeReady)return;try{
    gScene=new THREE.Scene();gCam=new THREE.PerspectiveCamera(42,1,.1,100);gCam.position.set(0,0,3.1);
    gRend=new THREE.WebGLRenderer({canvas:gCanvas,antialias:true,alpha:true});gRend.setClearAlpha(0);gGlobe=new THREE.Group();gScene.add(gGlobe);
    var pts=[],tries=0;while(pts.length<2400&&tries<24000){tries++;var v=Math.random();var lat=90-Math.acos(2*v-1)*180/Math.PI,lon=Math.random()*360-180;if(isLand(lat,lon)){var p=vLL(lat,lon,1.001);pts.push(p.x,p.y,p.z);}}
    var geo=new THREE.BufferGeometry();geo.setAttribute('position',new THREE.Float32BufferAttribute(pts,3));
    gGlobe.add(new THREE.Points(geo,new THREE.PointsMaterial({size:.03,map:disc('#7df9ff'),transparent:true,opacity:.95,depthWrite:false,blending:THREE.AdditiveBlending,color:0x3ee9ff})));
    gGlobe.add(new THREE.Mesh(new THREE.SphereGeometry(.985,42,42),new THREE.MeshBasicMaterial({color:0x3ee9ff,transparent:true,opacity:.1,depthWrite:false})));
    gGlobe.add(new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.SphereGeometry(1.004,22,14)),new THREE.LineBasicMaterial({color:0xa5b4fc,transparent:true,opacity:.16})));
    var atmo=new THREE.ShaderMaterial({transparent:true,side:THREE.BackSide,blending:THREE.AdditiveBlending,depthWrite:false,uniforms:{c:{value:new THREE.Color(0xc4b5fd)}},vertexShader:'varying vec3 vN;void main(){vN=normalize(normalMatrix*normal);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}',fragmentShader:'varying vec3 vN;uniform vec3 c;void main(){float i=pow(.72-dot(vN,vec3(0,0,1.)),2.6);gl_FragColor=vec4(c,1.)*i;}'});
    gScene.add(new THREE.Mesh(new THREE.SphereGeometry(1.22,42,42),atmo));
    breaches.forEach(function(b){var col=b.sev==='c'?0xff6b81:b.sev==='h'?0xfcd34d:0x7df9ff;var base=vLL(b.lat,b.lon,1.005);b._gv=base.clone().normalize();var sp=new THREE.Sprite(new THREE.SpriteMaterial({map:disc('#ffffff'),color:col,transparent:true,opacity:.95,depthWrite:false,blending:THREE.AdditiveBlending}));sp.position.copy(base);sp.scale.setScalar(.07);gGlobe.add(sp);var top=base.clone().multiplyScalar(1.12);gGlobe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([base,top]),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.55})));});
    for(var i=0;i<9;i++){var a=pick(breaches),b=pick(CITIES);var pa=vLL(a.lat,a.lon,1.005),pb=vLL(b[1],b[2],1.005);var mid=pa.clone().add(pb).multiplyScalar(.5).normalize().multiplyScalar(1.3);var cv=new THREE.QuadraticBezierCurve3(pa,mid,pb);var col=a.sev==='c'?0xff6b81:0x3ee9ff;gGlobe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(cv.getPoints(48)),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.28})));var tr=new THREE.Sprite(new THREE.SpriteMaterial({map:disc('#ffffff'),color:col,transparent:true,opacity:.95,depthWrite:false,blending:THREE.AdditiveBlending}));tr.scale.setScalar(.045);gGlobe.add(tr);gArcs.push({cv:cv,sp:tr,t:Math.random(),spd:.002+Math.random()*.002});}
    globeReady=true;resizeGlobe();
    var dg=false,lx=0,ly=0;gCanvas.addEventListener('pointerdown',function(e){dg=true;lx=e.clientX;ly=e.clientY;gAuto=false;});
    addWin('pointerup',function(){dg=false;if(!gWarp)setTimeout(function(){gAuto=true;},1500);});
    addWin('pointermove',function(e){if(!dg||gWarp)return;gGlobe.rotation.y+=(e.clientX-lx)*.005;gGlobe.rotation.x+=(e.clientY-ly)*.005;gGlobe.rotation.x=Math.max(-1.1,Math.min(1.1,gGlobe.rotation.x));lx=e.clientX;ly=e.clientY;});
  }catch(err){console.warn(err);}}
  function resizeGlobe(){if(!globeReady)return;var r=gCanvas.getBoundingClientRect();if(!r.width||!r.height)return;gRend.setPixelRatio(Math.min(2,window.devicePixelRatio||1));gRend.setSize(r.width,r.height,false);gCam.aspect=r.width/r.height;gCam.updateProjectionMatrix();}
  function drawGlobe(){if(!globeReady||dir!=='nebula')return;if(gAuto&&!gWarp&&!R)gGlobe.rotation.y+=.0016;gArcs.forEach(function(a){if(!R){a.t+=a.spd;if(a.t>1)a.t=0;}a.sp.position.copy(a.cv.getPoint(a.t));});if(gQuatT)gGlobe.quaternion.slerp(gQuatT,.07);if(gWarp)stepGWarp(performance.now());gRend.render(gScene,gCam);}
  function beginGWarp(b){if(gWarp)return;gAuto=false;gQuatT=new THREE.Quaternion().setFromUnitVectors(b._gv.clone(),new THREE.Vector3(0,0,1));gWarp={b:b,ph:'in',t0:performance.now(),from:gCam.position.z};document.getElementById('warpBtn').disabled=true;fireLockCard(b);spikeEkg();pushCortex(true);}
  function stepGWarp(now){var wS=gWarp,el=now-wS.t0;if(wS.ph==='in'){var p=Math.min(1,el/1200);gCam.position.z=wS.from+(1.45-wS.from)*(1-Math.pow(1-p,3));if(p>=1){wS.ph='hold';wS.t0=now;}}else if(wS.ph==='hold'){if(now-wS.t0>2400){wS.ph='out';wS.t0=now;wS.from=gCam.position.z;hideLockCard();}}else{var p2=Math.min(1,(now-wS.t0)/1000);gCam.position.z=wS.from+(3.1-wS.from)*(1-Math.pow(1-p2,3));if(p2>=1){gWarp=null;gQuatT=null;gAuto=true;document.getElementById('warpBtn').disabled=false;}}}

  var lockCardEl=document.getElementById('lockcard');
  function fireLockCard(b){lockCardEl.innerHTML='<div class="lt">◎ '+(LANG==='he'?'מטרה ננעלה':'Target locked')+' · '+(b.sev==='c'?'CRITICAL':b.sev==='h'?'HIGH':'MED')+'</div><div class="ld">'+b.domain+'</div><div class="lg"><span>NODE</span><b>'+b.name+'</b><span>CVE</span><b>'+b.cve+'</b><span>VECTOR</span><b>'+b.vector+'</b><span>ENGINE</span><b>'+b.engine+'</b><span>GEO</span><b>'+b.lat.toFixed(1)+', '+b.lon.toFixed(1)+'</b><span>RISK</span><b style="color:var(--crit)">'+b.score+'/100</b></div>';lockCardEl.classList.add('on');pushFinding(b,true);}
  function hideLockCard(){lockCardEl.classList.remove('on');lockTarget=null;lockAnim=0;}

  var warm=document.getElementById('warm');
  function spikeEkg(){ekgAmp=2.4;var bp=document.getElementById('bpm');bp.textContent=(108+rnd(18))+' bpm';bp.style.color='var(--crit)';var wb=document.getElementById('wrBpm');wb.textContent=(120+rnd(20))+' bpm';wb.style.color='var(--crit)';setTimeout(function(){bp.textContent=(66+rnd(10))+' bpm';bp.style.color='var(--a1)';wb.textContent=(84+rnd(12))+' bpm';wb.style.color='var(--a1)';},4000);}
  function incident(){var b=pick(breaches.filter(function(x){return x.sev==='c';}))||breaches[0];pushCortex(true);spikeEkg();pushFinding(b,true);councilItems.unshift({act:'Isolate host',tgt:b.domain,p:8});renderCouncil();wrPushComms('ESCALATE '+b.domain);
    if(dir==='nebula'){if(!globeReady)initGlobe();beginGWarp(b);}
    else if(dir==='holo'){lockTarget=b;lockAnim=0;setTimeout(function(){fireLockCard(b);},500);setTimeout(hideLockCard,4200);}
    else{warm.style.opacity='.9';fireLockCard(b);setTimeout(function(){warm.style.opacity='0';},2600);setTimeout(hideLockCard,4200);}}
  document.getElementById('incidentBtn').addEventListener('click',incident);
  document.getElementById('warpBtn').addEventListener('click',function(){var b=pick(breaches.filter(function(x){return x.sev==='c';}))||breaches[0];if(dir==='nebula'){if(!globeReady)initGlobe();beginGWarp(b);}else{lockTarget=b;lockAnim=0;fireLockCard(b);setTimeout(hideLockCard,4200);}});
  if(!R)IV(function(){if(Math.random()<.5)incident();},17000);
  mapCv.addEventListener('click',function(e){var r=mapCv.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top,best=null,bd=1e9;breaches.forEach(function(b){if(b._mx==null)return;var d=Math.hypot(b._mx-mx,b._my-my);if(d<bd){bd=d;best=b;}});if(best&&bd<26){lockTarget=best;lockAnim=0;fireLockCard(best);setTimeout(hideLockCard,4200);}});

  /* ══════════ WAR ROOM ══════════ */
  var ACTORS=[['APT29','🇷🇺',94],['Lazarus','🇰🇵',88],['APT41','🇨🇳',82],['Sandworm','🇷🇺',77],['Scattered Spider','🏴',71],['Charming Kitten','🇮🇷',66]];
  var KILL=['Recon','Weaponize','Deliver','Exploit','Install','C2','Actions'];
  var CAMP_NAMES=['Operation Nightfall','Silent Harvest','Crimson Tide','Ghost Protocol','Iron Veil','Black Lotus'];
  var campaigns=[];for(var ci=0;ci<4;ci++)campaigns.push({name:CAMP_NAMES[ci],actor:ACTORS[ci][0],stage:1+rnd(5)});
  var killStage=3;
  var wrCanvas=document.getElementById('wrCanvas'),wrDots=null;
  var defconLevel=3;

  function wrBuild(){
    // DEFCON
    var seg=document.getElementById('defconSegs');seg.innerHTML='';var cols=['#4ade80','#a3e635','#fcd34d','#fb923c','#ff6b81'];
    for(var i=1;i<=5;i++){var s=document.createElement('div');s.className='seg';if(i>=defconLevel)s.style.background=cols[i-1];seg.appendChild(s);}
    document.getElementById('defconLvl').textContent=defconLevel;
    // campaigns
    var cel=document.getElementById('wrCampaigns');cel.innerHTML='';campaigns.forEach(function(c){var d=document.createElement('div');d.className='camp';
      d.innerHTML='<div class="cn"><span>'+c.name+'</span><span style="color:var(--crit)">'+KILL[c.stage]+'</span></div><div class="ca">'+c.actor+' · '+(LANG==='he'?'שלב':'stage')+' '+(c.stage+1)+'/7</div><div class="cbar2"><i style="width:'+((c.stage+1)/7*100)+'%"></i></div>';cel.appendChild(d);});
    document.getElementById('campN').textContent=campaigns.length+' '+(LANG==='he'?'פעילים':'active');
    // actors
    var ael=document.getElementById('wrActors');ael.innerHTML='';ACTORS.forEach(function(a){var d=document.createElement('div');d.className='actor';d.innerHTML='<span class="fl">'+a[1]+'</span><span class="an">'+a[0]+' <small>· '+(LANG==='he'?'ייחוס':'attrib')+'</small></span><span class="ap">'+a[2]+'%</span>';ael.appendChild(d);});
    // kill-chain
    var kel=document.getElementById('wrKill');kel.innerHTML='';KILL.forEach(function(s,i){var d=document.createElement('div');d.className='kstage'+(i<killStage?' done':i===killStage?' active':'');d.innerHTML='<span class="kd"></span>'+s;kel.appendChild(d);});
  }
  function wrPushComms(extra){var el=document.getElementById('wrComms');if(!el)return;var acts=['AUTHORIZED containment','DISPATCHED blue team','ISOLATED subnet','TRACED to '+pick(ACTORS)[0],'COUNTER-STRIKE staged','HONEYPOT engaged'];
    var d=document.createElement('div');d.className='cm';d.innerHTML='<b>['+new Date().toISOString().slice(11,19)+']</b> '+(extra||pick(acts))+(extra?'':' · '+pick(COMPANIES));el.insertBefore(d,el.firstChild);while(el.children.length>16)el.removeChild(el.lastChild);}
  for(var wc=0;wc<6;wc++)wrPushComms();
  IV(function(){if(state.view==='warroom')wrPushComms();},2000);
  IV(function(){killStage=(killStage+1)%7;if(Math.random()<.5)campaigns.forEach(function(c){c.stage=Math.min(6,c.stage+(Math.random()<.4?1:0));});defconLevel=2+rnd(3);
    var rb=30+rnd(40);document.getElementById('rbRed').style.width=rb+'%';document.getElementById('rbBlue').style.width=(100-rb)+'%';wrBuild();},2600);

  function drawWar(){var g=fit(wrCanvas),w=g.w,h=g.h,x=g.x;x.clearRect(0,0,w,h);var now=performance.now(),cx=w/2,cy=h*.52;
    if(!wrDots||wrDots._w!==w){wrDots=[];for(var i=0;i<1200;i++){var lat=90-Math.acos(2*Math.random()-1)*180/Math.PI,lon=Math.random()*360-180;if(isLand(lat,lon))wrDots.push(mapProj(lat,lon,w,h));}wrDots._w=w;}
    x.fillStyle='rgba(62,233,255,0.22)';for(var i=0;i<wrDots.length;i++)x.fillRect(wrDots[i][0],wrDots[i][1],1.2,1.2);
    // range rings
    for(var rr=1;rr<=3;rr++){x.strokeStyle='rgba(165,180,252,'+(.16-rr*.03)+')';x.lineWidth=1;x.beginPath();x.arc(cx,cy,Math.min(w,h)*.16*rr,0,7);x.stroke();}
    // radar sweep
    if(!R){var sweep=now*.0009%(Math.PI*2);var grad=x.createRadialGradient(cx,cy,0,cx,cy,Math.min(w,h)*.5);grad.addColorStop(0,'rgba(62,233,255,0.18)');grad.addColorStop(1,'rgba(62,233,255,0)');x.save();x.beginPath();x.moveTo(cx,cy);x.arc(cx,cy,Math.min(w,h)*.5,sweep-.4,sweep);x.closePath();x.fillStyle=grad;x.fill();x.restore();}
    // converging attack arcs
    breaches.forEach(function(b){var p=mapProj(b.lat,b.lon,w,h);var col=b.sev==='c'?'255,107,129':b.sev==='h'?'252,211,77':'62,233,255';
      var mx=(p[0]+cx)/2,my=(p[1]+cy)/2-80;x.strokeStyle='rgba('+col+',0.4)';x.lineWidth=1.3;x.beginPath();x.moveTo(p[0],p[1]);x.quadraticCurveTo(mx,my,cx,cy);x.stroke();
      var tt=(now*.0004+b.id*.13)%1,ix=(1-tt)*(1-tt)*p[0]+2*(1-tt)*tt*mx+tt*tt*cx,iy=(1-tt)*(1-tt)*p[1]+2*(1-tt)*tt*my+tt*tt*cy;
      x.fillStyle='rgb('+col+')';x.shadowColor='rgb('+col+')';x.shadowBlur=8;x.beginPath();x.arc(ix,iy,2.2,0,7);x.fill();x.shadowBlur=0;
      var pr=2.4+Math.sin(now*.004+b.id)*1;x.fillStyle='rgb('+col+')';x.beginPath();x.arc(p[0],p[1],pr,0,7);x.fill();});
    // HQ core
    var pulse=1+Math.sin(now*.005)*.3;x.fillStyle='#a5b4fc';x.shadowColor='#a5b4fc';x.shadowBlur=24*pulse;x.beginPath();x.arc(cx,cy,8,0,7);x.fill();x.shadowBlur=0;
    x.strokeStyle='rgba(224,179,255,0.7)';x.lineWidth=1.5;x.beginPath();x.arc(cx,cy,14*pulse,0,7);x.stroke();
    document.getElementById('wrCount').textContent=breaches.length;}

  var wrEkg=document.getElementById('wrEkg');
  document.getElementById('wrStrikeBtn').addEventListener('click',function(){var b=pick(breaches);wrPushComms('COUNTER-STRIKE → '+b.domain);spikeEkg();defconLevel=Math.max(1,defconLevel-1);wrBuild();});
  document.querySelectorAll('#view-warroom .respbtns button').forEach(function(bn){bn.addEventListener('click',function(){wrPushComms(bn.textContent.toUpperCase());});});
  wrBuild();

  /* ══ menu / nav / views ══ */
  var NAVGROUPS=[
    ['Command','◈',[['Findings','/findings'],['Live Feed','/live-feed'],['Jobs','/jobs'],['Pulse','/pulse']]],
    ['Intelligence','🎯',[['Threat Intel','/threat-intel'],['Threat Hunting','/threat-hunting'],['Dark Web','/dark-web'],['Neural Web','/neural-web'],['Identity Matrix','/identity-matrix']]],
    ['Operations','⚔',[['Campaigns','/campaigns'],['Kill-Chain','/kill-chain'],['Deception','/deception'],['Auto-Heal','/auto-heal'],['Swarm-Mind','/swarm-mind'],['Edge Swarm','/edge-swarm']]],
    ['Engines','⬡',[['Engine Room','/engines'],['PQC Radar','/pqc-radar'],['ITDR','/itdr'],['Cloud Posture','/cloud-posture'],['Supply-Chain','/supply-chain']]],
    ['Governance','🛡',[['Security Posture','/security-posture'],['Compliance','/compliance'],['AI-Model-Risk','/ai-model-risk'],['Risk Graph','/risk-graph']]],
    ['Administration','👑',[['Mission Control','/mission-control'],['CEO Vault','/ceo-vault'],['Audit Log','/audit-log'],['Board Pack','/board-pack']]]
  ];
  var GROUP_HE={Command:'פיקוד',Intelligence:'מודיעין',Operations:'מבצעים',Engines:'מנועים',Governance:'ממשל',Administration:'ניהול'};
  function buildMenuNav(){var host=document.getElementById('menuNav');if(!host)return;host.innerHTML='';
    NAVGROUPS.forEach(function(g){var gd=document.createElement('div');gd.className='menu-group';var title=LANG==='he'?(GROUP_HE[g[0]]||g[0]):g[0];
      var inner='<div class="gt">'+title+'</div>';g[2].forEach(function(it){inner+='<div class="menu-item"><span class="mi-ic">'+g[1]+'</span><span>'+it[0]+'</span><span class="mi-r">'+it[1]+'</span></div>';});gd.innerHTML=inner;host.appendChild(gd);});}
  buildMenuNav();

  var scrim=document.getElementById('scrim'),menu=document.getElementById('menu'),menuOpen=false;
  function openMenu(){menuOpen=true;menu.classList.add('on');scrim.classList.add('on');}
  function closeMenu(){menuOpen=false;menu.classList.remove('on');scrim.classList.remove('on');}
  document.getElementById('menuBtn').addEventListener('click',openMenu);
  document.getElementById('menuClose').addEventListener('click',closeMenu);
  scrim.addEventListener('click',closeMenu);

  var state={view:'cockpit',hist:[]};
  function showView(v){state.view=v;document.getElementById('view-cockpit').classList.toggle('on',v==='cockpit');document.getElementById('view-warroom').classList.toggle('on',v==='warroom');
    document.querySelectorAll('.launch button').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-go')===v);});
    document.getElementById('content').scrollTop=0;setTimeout(resizeAll,30);updateBack();}
  function goView(v){if(v===state.view){closeMenu();return;}state.hist.push(state.view);showView(v);closeMenu();}
  function goBack(){if(menuOpen){closeMenu();return;}if(state.hist.length){showView(state.hist.pop());}}
  function updateBack(){document.getElementById('backBtn').disabled=(state.hist.length===0);}
  document.querySelectorAll('.launch button').forEach(function(b){b.addEventListener('click',function(){goView(b.getAttribute('data-go'));});});
  document.getElementById('backBtn').addEventListener('click',goBack);
  updateBack();

  /* language */
  document.getElementById('langBtn').addEventListener('click',function(){var nl=(LANG==='en'?'he':'en');applyLang(nl);if(opts.onLangChange)opts.onLangChange(nl);});

  /* ══ master loop ══ */
  var last=0;
  function loop(t){if(disposed)return;requestAnimationFrame(loop);if(t-last<33)return;last=t;
    try{
      if(state.view==='cockpit'){if(dir==='nebula')drawGlobe();else drawMap();drawEkgOn(document.getElementById('ekgCanvas'),true);drawEngine();drawNeural();drawSwarm();drawEdge();document.getElementById('theaterCount').textContent=breaches.length;}
      else if(state.view==='warroom'){drawWar();drawEkgOn(wrEkg,true);}
    }catch(e){}
  }
  requestAnimationFrame(loop);

  function resizeAll(){cssCache={};cssDir='';if(dir==='nebula')resizeGlobe();mapDots=null;wrDots=null;if(neuNodes)neuNodes._w=-1;if(swP)swP._w=-1;}
  addWin('resize',function(){clearTimeout(window._rz);window._rz=setTimeout(resizeAll,120);});

  /* boot */
  initGlobe();
  applyLang(opts.initialLang==='he'?'he':'en');
  if(opts.initialView==='warroom'||location.hash==='#warroom'){state.hist.push('cockpit');showView('warroom');}
  addWin('hashchange',function(){goView(location.hash==='#warroom'?'warroom':'cockpit');});
  setTimeout(resizeAll,90);

  return function cleanup() {
    disposed = true;
    _timers.forEach(function (id) { clearInterval(id); });
    _win.forEach(function (w) { window.removeEventListener(w[0], w[1], w[2]); });
    try { if (typeof gRend !== 'undefined' && gRend && gRend.dispose) gRend.dispose(); } catch (e) {}
  };
}
