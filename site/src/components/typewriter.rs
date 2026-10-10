use gloo::timers::callback::Interval;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct TypewriterProps {
    pub words: &'static [&'static str],
}

#[derive(Clone, Copy, PartialEq)]
struct State {
    word: usize,
    chars: usize,
    deleting: bool,
    pause: u8,
}

/// Types and deletes words in a loop.
#[component]
pub fn Typewriter(props: &TypewriterProps) -> Html {
    let state = use_state(|| State {
        word: 0,
        chars: 0,
        deleting: false,
        pause: 0,
    });
    let words = props.words;

    {
        let state = state.clone();
        use_effect_with(words, move |words| {
            let words = *words;
            state.set(State {
                word: 0,
                chars: 0,
                deleting: false,
                pause: 0,
            });
            let state2 = state.clone();
            let interval = Interval::new(65, move || {
                let mut s = *state2;
                let len = words[s.word % words.len()].chars().count();
                if s.pause > 0 {
                    s.pause -= 1;
                } else if !s.deleting {
                    if s.chars < len {
                        s.chars += 1;
                    } else {
                        s.deleting = true;
                        s.pause = 28;
                    }
                } else if s.chars > 0 {
                    s.chars -= 1;
                } else {
                    s.deleting = false;
                    s.word = (s.word + 1) % words.len();
                    s.pause = 4;
                }
                state2.set(s);
            });
            move || drop(interval)
        });
    }

    let word = words[state.word % words.len()];
    let shown: String = word.chars().take(state.chars).collect();
    html! {
        <span class="typewriter">
            <span class="gradient-text">{ shown }</span>
            <span class="caret" aria-hidden="true"></span>
            <span class="sr-only">{ word }</span>
        </span>
    }
}
