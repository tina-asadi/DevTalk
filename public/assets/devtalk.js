// DevTalk — small progressive-enhancement helpers.
// The delete-confirm prompts used to be inline onsubmit="confirm(...)" handlers,
// which a strict CSP blocks. They now live here so the policy needs no
// 'unsafe-inline'. Lab 8.
document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
        if (!window.confirm(form.getAttribute('data-confirm'))) {
            event.preventDefault();
        }
    });
});
