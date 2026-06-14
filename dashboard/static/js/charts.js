// ── Validation Chart ──
const validationCanvas = document.getElementById("validationChart");

if (validationCanvas && window.validationData) {

    const ruleCounts = {};

    window.validationData.labels.forEach((label, i) => {
        if (!ruleCounts[label]) {
            ruleCounts[label] = { PASS: 0, FAIL: 0, FP: 0 };
        }

        const result = window.validationData.results[i];

        if (ruleCounts[label][result] !== undefined) {
            ruleCounts[label][result] += 1;
        }
    });

    const ruleLabels = Object.keys(ruleCounts);
    const passData = ruleLabels.map(r => ruleCounts[r].PASS);
    const failData = ruleLabels.map(r => ruleCounts[r].FAIL);
    const fpData = ruleLabels.map(r => ruleCounts[r].FP);

    new Chart(validationCanvas, {
        type: "bar",
        data: {
            labels: ruleLabels,
            datasets: [
                {
                    label: "PASS",
                    data: passData,
                    backgroundColor: "#56d36455",
                    borderColor: "#56d364",
                    borderWidth: 1
                },
                {
                    label: "FAIL",
                    data: failData,
                    backgroundColor: "#ff6b6b55",
                    borderColor: "#ff6b6b",
                    borderWidth: 1
                },
                {
                    label: "FP",
                    data: fpData,
                    backgroundColor: "#ffaa0055",
                    borderColor: "#ffaa00",
                    borderWidth: 1
                }
            ]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: "#c9d1d9" },
                    grid: { color: "#30363d" }
                },
                x: {
                    ticks: { color: "#c9d1d9" },
                    grid: { color: "#30363d" }
                }
            },
            plugins: {
                legend: {
                    labels: { color: "#c9d1d9" }
                }
            }
        }
    });
}

// ── Metrics Chart ──
const metricsCanvas = document.getElementById("metricsChart");

if (metricsCanvas) {
    const metricsTable = document.getElementById("metricsTable");
    const rows = metricsTable.querySelectorAll("tr");

    const labels = [];
    const rates = [];

    rows.forEach((row, index) => {
        if (index === 0) return;

        const cells = row.querySelectorAll("td");

        if (cells.length > 0) {
            labels.push(cells[0].innerText);

            // Detection Rate column is index 6 in the improved table
            rates.push(parseFloat(cells[6].innerText));
        }
    });

    new Chart(metricsCanvas, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Detection Rate %",
                data: rates,
                backgroundColor: "#58a6ff55",
                borderColor: "#58a6ff",
                borderWidth: 1
            }]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: "#c9d1d9" },
                    grid: { color: "#30363d" }
                },
                x: {
                    ticks: { color: "#c9d1d9" },
                    grid: { color: "#30363d" }
                }
            },
            plugins: {
                legend: {
                    labels: { color: "#c9d1d9" }
                }
            }
        }
    });
}