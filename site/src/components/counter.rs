use std::cell::RefCell;
use std::rc::Rc;

use gloo::render::{AnimationFrame, request_animation_frame};
use yew::prelude::*;

use crate::hooks::{prefers_reduced_motion, use_in_view};

#[derive(Properties, PartialEq)]
pub struct CounterProps {
    pub to: f64,
    #[prop_or_default]
    pub decimals: usize,
    #[prop_or_default]
    pub prefix: AttrValue,
    #[prop_or_default]
    pub suffix: AttrValue,
    #[prop_or(1600.0)]
    pub duration: f64,
}

/// Counts up from 0 when scrolled into view (ease-out cubic).
#[component]
pub fn Counter(props: &CounterProps) -> Html {
    let node = use_node_ref();
    let seen = use_in_view(node.clone());
    let value = use_state(|| 0.0_f64);

    {
        let value = value.clone();
        let (to, duration) = (props.to, props.duration);
        use_effect_with(seen, move |seen| {
            let handle: Rc<RefCell<Option<AnimationFrame>>> = Rc::new(RefCell::new(None));
            if *seen {
                if prefers_reduced_motion() {
                    value.set(to);
                } else {
                    let start = js_sys::Date::now();
                    fn step(
                        start: f64,
                        to: f64,
                        duration: f64,
                        value: UseStateHandle<f64>,
                        handle: Rc<RefCell<Option<AnimationFrame>>>,
                    ) {
                        let t = ((js_sys::Date::now() - start) / duration).min(1.0);
                        let eased = 1.0 - (1.0 - t).powi(3);
                        value.set(to * eased);
                        if t < 1.0 {
                            let h2 = handle.clone();
                            let next = request_animation_frame(move |_| {
                                step(start, to, duration, value, h2)
                            });
                            *handle.borrow_mut() = Some(next);
                        }
                    }
                    step(start, to, duration, value, handle.clone());
                }
            }
            move || {
                handle.borrow_mut().take();
            }
        });
    }

    let shown = format!("{:.*}", props.decimals, *value);
    html! {
        <span ref={node} class="counter">{ &props.prefix }{ shown }{ &props.suffix }</span>
    }
}
