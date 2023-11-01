window.GOVUKFrontend.initAll();

function runDetectBack() {
    var detect_back = document.getElementById("detect_back");
    if (detect_back) {
        if (detect_back.value == "0") {
            console.log("UK Government SSO: First load");
            detect_back.value = "1";
        } else {
            console.log("UK Government SSO: Back event detected");
            var force_email = document.getElementById("force_email");
            if (force_email) {
                force_email.value = "true";
                document.getElementById("divForceEmailNotice").classList.remove("hidden");
            }
        }
    }
}
window.addEventListener('pageshow', runDetectBack);
