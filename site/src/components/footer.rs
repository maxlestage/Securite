use yew::prelude::*;
use yew_router::prelude::*;

use crate::i18n::Lang;
use crate::icons::Icon;
use crate::{CRATES_IO, DOCS_RS, REPO, Route, use_lang};

#[component]
pub fn Footer() -> Html {
    let ctx = use_lang();
    let t = ctx.lang.t();
    let doc = |slug: &str, label: &'static str| {
        html! { <li><Link<Route> to={Route::Doc { slug: slug.into() }}>{ label }</Link<Route>></li> }
    };
    let ext = |href: String, label: &'static str| {
        html! { <li><a href={href} target="_blank" rel="noopener noreferrer">{ label }</a></li> }
    };
    let year = js_sys::Date::new_0().get_full_year();

    html! {
        <footer class="footer">
            <div class="footer-glow" aria-hidden="true"></div>
            <div class="container footer-grid">
                <div class="footer-brand">
                    <Link<Route> to={Route::Home} classes="brand">
                        <span class="brand-mark"><Icon name="shield-check" size={22} /></span>
                        <span class="brand-name">{"securite"}</span>
                    </Link<Route>>
                    <p class="muted">{ t.footer_tagline }</p>
                    <div class="footer-langs" role="group" aria-label={t.language}>
                        { for Lang::ALL.iter().map(|l| {
                            let l = *l;
                            let set = ctx.set.clone();
                            html! {
                                <button class={classes!("chip", (l == ctx.lang).then_some("active"))}
                                    onclick={Callback::from(move |_| set.emit(l))}>{ l.label() }</button>
                            }
                        }) }
                    </div>
                    <div class="socials">
                        <a class="icon-btn" href={REPO} target="_blank" rel="noopener noreferrer" aria-label="GitHub"><Icon name="github" /></a>
                        <a class="icon-btn" href={CRATES_IO} target="_blank" rel="noopener noreferrer" aria-label="crates.io"><Icon name="crate" /></a>
                        <a class="icon-btn" href={DOCS_RS} target="_blank" rel="noopener noreferrer" aria-label="docs.rs"><Icon name="book" /></a>
                    </div>
                </div>
                <div>
                    <h4>{ t.footer_product }</h4>
                    <ul>
                        <li><Link<Route> to={Route::Home}>{ t.nav_home }</Link<Route>></li>
                        <li><Link<Route> to={Route::Playground}>{ t.nav_playground }</Link<Route>></li>
                        { doc("waf", "WAF") }
                        { doc("rate-limit", "Rate limiting") }
                        { doc("security-headers", "Security headers") }
                    </ul>
                </div>
                <div>
                    <h4>{ t.footer_docs }</h4>
                    <ul>
                        { doc("introduction", "Introduction") }
                        { doc("quick-start", "Quick start") }
                        { doc("shield-presets", "Presets") }
                        { doc("custom-guards", "Custom guards") }
                        <li><Link<Route> to={Route::Docs}>{ t.docs_back }</Link<Route>></li>
                    </ul>
                </div>
                <div>
                    <h4>{ t.footer_resources }</h4>
                    <ul>
                        { ext(CRATES_IO.into(), "crates.io") }
                        { ext(DOCS_RS.into(), "docs.rs") }
                        { doc("heroku-from-phone", "Heroku") }
                        { ext(format!("{REPO}/blob/master/CHANGELOG.md"), t.footer_changelog) }
                        { ext(format!("{REPO}/blob/master/SECURITY.md"), t.footer_security) }
                    </ul>
                </div>
                <div>
                    <h4>{ t.footer_community }</h4>
                    <ul>
                        { ext(REPO.into(), "GitHub") }
                        { ext(format!("{REPO}/issues"), t.footer_issues) }
                        { ext(format!("{REPO}/pulls"), t.footer_contribute) }
                        { ext(format!("{REPO}/blob/master/LICENSE-MIT"), t.footer_license) }
                    </ul>
                </div>
            </div>
            <div class="container footer-bottom">
                <span>{ format!("© {year} securite. {}", t.footer_rights) }</span>
                <span class="made">{ t.footer_made }{" · "}<span class="rust">{"🦀"}</span></span>
            </div>
        </footer>
    }
}
