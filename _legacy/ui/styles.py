"""
Design system — Ghrab VOC.

"Command Center" redesign: a dark forest chrome (topbar + sidebar) frames a
light cream content canvas, so the operator always knows what's navigation
vs. what's data. Cards are elevated with soft shadows and a top accent bar
rather than flat borders. Status is still carried by color + shape + an
explicit text label — never an icon glyph, no emoji anywhere in the product.
"""

# --- Brand palette -----------------------------------------------------
CREAM = "#F7F2EE"  # content canvas background
INK = "#272529"  # primary text
FOREST = "#003C30"  # primary brand — deep green (chrome / primary actions)
SAGE_MED = "#55A185"  # brand accent — medium green
SAGE = "#88A682"  # brand accent — soft green
WHITE = "#FFFFFF"

# secondary palette
PALE_SAGE = "#B4CEB4"
DUSTY_BLUE = "#A4BDCE"
TERRACOTTA = "#C96048"
GOLD = "#F0E689"

# derived tints (shades of the above, kept in-family — not new hues)
FOREST_DEEP = "#00251E"  # near-black forest, for chrome gradients
FOREST_TINT = "#0B5A48"
FOREST_GLOW = "rgba(85,161,133,0.35)"  # sage-med glow for chrome accents
TERRACOTTA_DEEP = "#A34632"
GOLD_DEEP = "#B98F1E"  # deepened gold — GOLD itself fails text contrast
DUSTY_BLUE_DEEP = "#5D7C93"
INK_MUTED = "#5B5954"
INK_FAINT = "#8C8A84"
BORDER = "rgba(39,37,41,0.10)"
BORDER_STRONG = "rgba(39,37,41,0.20)"
GRID_COLOR = "#E5E0D8"
CHART_FONT_COLOR = INK_MUTED
EDGE_COLOR = "#C9C2B6"
NODE_FALLBACK_COLOR = INK_FAINT

# --- Chart palettes ------------------------------------------------------
# Ordered for adjacent-category separation: alternate warm/cool, dark/light.
CATEGORICAL = [FOREST, TERRACOTTA, DUSTY_BLUE, GOLD_DEEP, SAGE_MED, TERRACOTTA_DEEP, SAGE, "#6E7F91"]
SEQUENTIAL_GREEN = ["#E4EEE8", "#C4DBCE", "#9EC4B0", "#6FA88C", "#3E8468", "#1B6249", FOREST]
DIVERGING = {"low": DUSTY_BLUE, "mid": "#EDE8E1", "high": TERRACOTTA}

# Severity ramp, most → least urgent. Derived entirely from the brand's
# secondary palette (terracotta family for danger, gold for caution, dusty
# blue for informational, medium green for healthy) rather than a generic
# red/amber/green traffic-light set.
STATUS = {
    "IMMEDIATE": {"color": TERRACOTTA_DEEP},
    "ACT": {"color": TERRACOTTA},
    "ATTEND": {"color": GOLD_DEEP},
    "TRACK*": {"color": DUSTY_BLUE_DEEP},
    "TRACK": {"color": SAGE_MED},
}

FONT_IMPORT = (
    "https://fonts.googleapis.com/css2?"
    "family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&"
    "family=Lato:wght@300;400;500;600;700;900&display=swap"
)

_GLOBAL_CSS_RAW = f"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="{FONT_IMPORT}" rel="stylesheet">
<style>
:root {{
 --cream: {CREAM}; --ink: {INK}; --ink-muted: {INK_MUTED}; --ink-faint: {INK_FAINT};
 --forest: {FOREST}; --forest-tint: {FOREST_TINT}; --forest-deep: {FOREST_DEEP}; --forest-glow: {FOREST_GLOW};
 --sage-med: {SAGE_MED}; --sage: {SAGE};
 --pale-sage: {PALE_SAGE}; --dusty-blue: {DUSTY_BLUE}; --dusty-blue-deep: {DUSTY_BLUE_DEEP};
 --terracotta: {TERRACOTTA}; --terracotta-deep: {TERRACOTTA_DEEP}; --gold: {GOLD}; --gold-deep: {GOLD_DEEP};
 --white: {WHITE}; --border: {BORDER}; --border-strong: {BORDER_STRONG};
 --font-serif: 'Libre Baskerville', Georgia, serif;
 --font-sans: 'Lato', -apple-system, 'Segoe UI', sans-serif;
 --radius-sm: 8px; --radius: 14px; --radius-lg: 20px; --radius-full: 999px;
 --shadow-sm: 0 1px 3px rgba(0,37,30,0.06), 0 1px 2px rgba(0,37,30,0.04);
 --shadow-md: 0 8px 24px rgba(0,37,30,0.08), 0 2px 6px rgba(0,37,30,0.05);
 --shadow-lg: 0 20px 48px rgba(0,37,30,0.16), 0 6px 16px rgba(0,37,30,0.08);
}}

html, body, [class*="css"] {{ font-family: var(--font-sans); }}

.stApp {{
 background:
   radial-gradient(1100px 480px at 100% -8%, rgba(85,161,133,0.10), transparent 60%),
   var(--cream);
}}
.block-container {{ padding-top: 4.4rem; padding-bottom: 6rem; max-width: 1480px; }}

header[data-testid="stHeader"] {{ background: transparent; }}

h1, h2, h3 {{ font-family: var(--font-serif); color: var(--ink); font-weight: 700; letter-spacing: -0.012em; }}
h4, h5, h6 {{ font-family: var(--font-sans); color: var(--ink); font-weight: 800; letter-spacing: -0.005em; }}
p, span, div, label, li {{ color: var(--ink); }}
.stMarkdown p {{ color: var(--ink-muted); line-height: 1.6; }}
::selection {{ background: var(--pale-sage); }}

/* thin, quiet scrollbars that fit the chrome */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: var(--border-strong); border-radius: 999px; border: 2px solid var(--cream); }}

/* ---------- Top navigation bar — dark forest chrome ---------- */
.voc-topbar {{
 display: flex; align-items: center; justify-content: space-between;
 padding: 1.05rem 1.6rem; margin: 0 -1px 1.3rem -1px;
 background: linear-gradient(120deg, var(--forest-deep) 0%, var(--forest) 55%, var(--forest-tint) 100%);
 border-radius: 0 0 var(--radius-lg) var(--radius-lg);
 box-shadow: var(--shadow-lg);
 position: relative; overflow: hidden;
}}
.voc-topbar::after {{
 content: ""; position: absolute; inset: 0;
 background: radial-gradient(600px 200px at 85% 0%, var(--forest-glow), transparent 70%);
 pointer-events: none;
}}
.voc-brand {{ display: flex; align-items: baseline; gap: 0.75rem; position: relative; z-index: 1; }}
.voc-brand .mark {{
 font-family: var(--font-serif); font-weight: 700; font-size: 1.6rem; color: var(--white);
 letter-spacing: 0.03em;
}}
.voc-brand .division {{
 font-family: var(--font-sans); font-size: 0.7rem; font-weight: 700; letter-spacing: 0.16em;
 text-transform: uppercase; color: var(--pale-sage); border-left: 1px solid rgba(255,255,255,0.22);
 padding-left: 0.7rem;
}}
.voc-topbar-right {{ display: flex; align-items: center; gap: 0.7rem; position: relative; z-index: 1; }}

.voc-mode-badge {{
 display: inline-flex; align-items: center; gap: 7px; font-size: 0.76rem; font-weight: 700;
 padding: 6px 15px; border-radius: var(--radius-full); border: 1px solid rgba(255,255,255,0.16);
 color: var(--white); background: rgba(255,255,255,0.08); backdrop-filter: blur(6px);
 font-family: var(--font-sans); letter-spacing: 0.01em;
}}
.voc-mode-badge .dot {{ width: 7px; height: 7px; border-radius: 999px; display: inline-block; }}
.voc-mode-badge.on .dot {{ background: var(--sage-med); box-shadow: 0 0 0 3px rgba(85,161,133,0.35); }}
.voc-mode-badge.off .dot {{ background: rgba(255,255,255,0.5); }}

/* ---------- Streamlit tabs restyled as a segmented pill nav ---------- */
.stTabs [data-baseweb="tab-list"] {{
 gap: 0.3rem; border-bottom: none; background: var(--white);
 padding: 0.35rem; border-radius: var(--radius); box-shadow: var(--shadow-sm);
 border: 1px solid var(--border); margin-bottom: 0.3rem;
}}
.stTabs [data-baseweb="tab"] {{
 height: auto; padding: 0.55rem 1.1rem; background: transparent; border-radius: var(--radius-sm);
 font-family: var(--font-sans); font-weight: 700; font-size: 0.87rem;
 color: var(--ink-faint); letter-spacing: 0.005em; transition: background 0.15s ease, color 0.15s ease;
}}
.stTabs [data-baseweb="tab"] p {{ color: inherit; font-size: 0.87rem; }}
.stTabs [data-baseweb="tab"]:hover {{ background: var(--cream); color: var(--ink-muted); }}
.stTabs [aria-selected="true"] {{ color: var(--white) !important; background: var(--forest); }}
.stTabs [aria-selected="true"] p {{ color: var(--white) !important; }}
.stTabs [aria-selected="true"]:hover {{ background: var(--forest); }}
.stTabs [data-baseweb="tab-highlight"] {{ background-color: transparent; }}
.stTabs [data-baseweb="tab-border"] {{ display: none; }}

/* ---------- Cards ---------- */
.kpi-card {{
 background: var(--white); border: 1px solid var(--border); border-radius: var(--radius);
 padding: 1.2rem 1.35rem 1.1rem 1.35rem; height: 100%; box-shadow: var(--shadow-sm);
 position: relative; overflow: hidden; transition: box-shadow 0.18s ease, transform 0.18s ease;
}}
.kpi-card::before {{
 content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
 background: linear-gradient(90deg, var(--forest), var(--sage-med));
}}
.kpi-card:hover {{ box-shadow: var(--shadow-md); transform: translateY(-2px); }}
.kpi-label {{ font-size: 0.7rem; color: var(--ink-faint); font-weight: 800;
 text-transform: uppercase; letter-spacing: 0.09em; margin-bottom: 8px; font-family: var(--font-sans); }}
.kpi-value {{ font-family: var(--font-serif); font-size: 2.15rem; font-weight: 700;
 color: var(--forest); line-height: 1.05; }}
.kpi-sub {{ font-size: 0.79rem; color: var(--ink-muted); margin-top: 6px; }}

.finding-card {{
 border: 1px solid var(--border); border-radius: var(--radius);
 padding: 0.95rem 1.15rem; margin-bottom: 0.6rem; background: var(--white);
 box-shadow: var(--shadow-sm); transition: box-shadow 0.15s ease, transform 0.15s ease;
 border-left-width: 4px; border-left-style: solid; border-left-color: var(--forest);
}}
.finding-card:hover {{ box-shadow: var(--shadow-md); transform: translateY(-1px); }}
.finding-card .title {{ font-weight: 800; font-size: 0.96rem; margin-bottom: 4px; color: var(--ink); }}
.finding-card .meta {{ color: var(--ink-muted); font-size: 0.8rem; }}

.chain-step {{
 position: relative; padding: 0.4rem 0 0.4rem 1.15rem; margin-bottom: 0.1rem;
 border-left: 2px solid var(--pale-sage);
}}
.chain-step::before {{
 content: ""; position: absolute; left: -5px; top: 0.65rem; width: 9px; height: 9px;
 border-radius: 999px; background: var(--sage-med); box-shadow: 0 0 0 3px var(--white);
}}
.chain-step .step-title {{ font-weight: 800; font-size: 0.89rem; color: var(--ink); }}
.chain-step .step-meta {{ color: var(--ink-muted); font-size: 0.77rem; margin-top: 1px; }}

.ai-box {{
 background: linear-gradient(165deg, rgba(180,206,180,0.28) 0%, var(--white) 55%);
 border: 1px solid var(--border); border-radius: var(--radius);
 padding: 1.1rem 1.3rem; font-size: 0.92rem; line-height: 1.65; color: var(--ink);
 box-shadow: var(--shadow-sm); position: relative;
}}
.ai-box::before {{
 content: ""; position: absolute; top: 0; left: 0; bottom: 0; width: 3px;
 border-radius: var(--radius) 0 0 var(--radius);
 background: linear-gradient(180deg, var(--forest), var(--sage-med));
}}
.ai-box .ai-label {{ font-size: 0.7rem; font-weight: 800; text-transform: uppercase;
 letter-spacing: 0.1em; color: var(--forest); margin-bottom: 8px; font-family: var(--font-sans);
 display: flex; align-items: center; gap: 6px; }}
.ai-box .ai-label::before {{
 content: ""; width: 6px; height: 6px; border-radius: 999px; background: var(--sage-med);
 display: inline-block;
}}

.status-pill {{
 display: inline-flex; align-items: center; gap: 6px; font-weight: 800; font-size: 0.7rem;
 padding: 4px 11px 4px 9px; border-radius: var(--radius-full); white-space: nowrap; letter-spacing: 0.04em;
 font-family: var(--font-sans); text-transform: uppercase;
}}
.status-pill .sq {{ width: 6px; height: 6px; border-radius: 999px; display: inline-block; }}

hr.voc-divider {{ border: none; border-top: 1px solid var(--border); margin: 1.6rem 0; }}

/* ---------- Streamlit control restyling ---------- */
.stButton > button {{
 font-family: var(--font-sans); font-weight: 700; border-radius: var(--radius-full);
 border: 1px solid var(--forest); transition: box-shadow 0.15s ease, transform 0.15s ease;
}}
.stButton > button[kind="primary"] {{
 background: linear-gradient(120deg, var(--forest), var(--forest-tint)); border-color: var(--forest);
 color: var(--white); box-shadow: var(--shadow-sm);
}}
.stButton > button[kind="primary"] p {{ color: var(--white); }}
.stButton > button[kind="primary"]:hover {{ box-shadow: var(--shadow-md); transform: translateY(-1px); }}
.stButton > button[kind="secondary"] {{ background: var(--white); color: var(--forest); border-radius: var(--radius-sm); }}
.stButton > button[kind="secondary"]:hover {{ border-color: var(--forest); color: var(--forest); box-shadow: var(--shadow-sm); }}

[data-testid="stMetricValue"] {{ font-family: var(--font-serif); font-size: 1.75rem; color: var(--forest); }}
[data-testid="stMetricLabel"] {{ font-family: var(--font-sans); font-weight: 800;
 text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.07em; color: var(--ink-faint); }}

section[data-testid="stSidebar"] {{
 background: linear-gradient(190deg, var(--forest-deep) 0%, var(--forest) 100%);
 border-right: none;
}}
section[data-testid="stSidebar"] * {{ color: var(--white); }}
section[data-testid="stSidebar"] h3 {{ font-size: 1.05rem; color: var(--white); font-family: var(--font-serif); }}
section[data-testid="stSidebar"] .stCaption, section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{
 color: var(--pale-sage) !important;
}}
section[data-testid="stSidebar"] hr {{ border-color: rgba(255,255,255,0.14); }}
section[data-testid="stSidebar"] .stButton > button[kind="primary"] {{
 background: linear-gradient(120deg, var(--sage-med), var(--sage)); border-color: var(--sage-med); color: var(--forest-deep);
}}
section[data-testid="stSidebar"] .stButton > button[kind="primary"] p {{ color: var(--forest-deep); font-weight: 800; }}
section[data-testid="stSidebar"] [data-testid="stCheckbox"] label p {{ color: var(--white); }}
section[data-testid="stSidebar"] [data-testid="stStatusWidget"], section[data-testid="stSidebar"] [data-testid="stExpander"] {{
 background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.14); border-radius: var(--radius);
}}
section[data-testid="stSidebar"] [data-testid="stAlertContentSuccess"] {{ color: var(--forest-deep) !important; }}
section[data-testid="stSidebar"] [data-testid="stAlertContentSuccess"] * {{ color: var(--forest-deep) !important; }}

[data-testid="stExpander"] {{ border: 1px solid var(--border); border-radius: var(--radius); background: var(--white); box-shadow: var(--shadow-sm); }}
[data-testid="stDataFrame"] {{ border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow-sm); }}

.stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] {{
 font-family: var(--font-sans); border-radius: var(--radius-sm) !important;
}}

/* ---------- Floating AI Analyst trigger ----------
 st.container(key="ai_fab") renders a wrapper with class "st-key-ai_fab" —
 pin that specific wrapper to the viewport corner; everything inside
 (the popover trigger button + panel) rides along untouched. */
.st-key-ai_fab {{ position: fixed; right: 2rem; bottom: 1.6rem; z-index: 999; width: auto; }}
.st-key-ai_fab [data-testid="stPopover"] > button {{
 background: linear-gradient(120deg, var(--forest-deep), var(--forest) 60%, var(--forest-tint));
 color: var(--white); border: none; border-radius: var(--radius-full);
 padding: 0.85rem 1.5rem; font-family: var(--font-sans); font-weight: 700; font-size: 0.88rem;
 box-shadow: 0 12px 32px rgba(0,37,30,0.38); letter-spacing: 0.01em;
 transition: box-shadow 0.15s ease, transform 0.15s ease;
}}
.st-key-ai_fab [data-testid="stPopover"] > button:hover {{
 box-shadow: 0 16px 40px rgba(0,37,30,0.46); transform: translateY(-2px);
}}
.st-key-ai_fab [data-testid="stPopover"] > button p {{ color: var(--white); font-weight: 700; }}
div[data-testid="stPopoverBody"] {{
 font-family: var(--font-sans); border-radius: var(--radius-lg); border: 1px solid var(--border-strong);
 width: 420px; box-shadow: var(--shadow-lg);
}}
</style>
"""

# Streamlit's markdown renderer treats <style>/<link> as a raw-HTML block
# only while lines are contiguous; a blank line inside it ends the block
# early and the remaining CSS gets parsed as Markdown text and rendered
# visibly on the page. Strip blank lines to keep the whole block intact.
GLOBAL_CSS = "\n".join(
    line for line in _GLOBAL_CSS_RAW.splitlines() if line.strip()
)


def status_pill_html(band: str) -> str:
    color = STATUS.get(band, {"color": INK_FAINT})["color"]
    return (f'<span class="status-pill" style="background:{color}1A;'
            f'color:{color};border:1px solid {color}55;">'
            f'<span class="sq" style="background:{color};"></span>{band}</span>')
