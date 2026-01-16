function goToMain() {
    window.location.href = '/';
}

function goToHelp() {
    window.location.href = '/help';
}

function goToProposal() {
    window.location.href = '/proposal';
}

function goToComplaint() {
    window.location.href = '/complaint';
}

function showModal() {
    document.getElementById('infoModal').style.display = 'flex';
}

function hideModal() {
    document.getElementById('infoModal').style.display = 'none';
}

document.addEventListener('DOMContentLoaded', function () {
    console.log('Main page loaded');

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            hideModal();
        }
    });

    document.getElementById('infoModal').addEventListener('click', function (event) {
        if (event.target === this) {
            hideModal();
        }
    });
});