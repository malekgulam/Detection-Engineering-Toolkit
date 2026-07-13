// ── Page Detection ─────────────────────────────────────
const onIndex   = typeof indexData   !== "undefined";
const onMetrics = typeof metricsData !== "undefined";
const onHistory = typeof historyData !== "undefined";

// ── Chart Defaults ─────────────────────────────────────
const C = {
    blue:   "#58a6ff",
    green:  "#3fb950",
    red:    "#f85149",
    yellow: "#d29922",
    purple: "#bc8cff",
    muted:  "#7d8590",
    border: "#30363d",
    text:   "#e6edf3"
};

function baseBarOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        indexAxis: "y",
        plugins: {
            legend: { display: false },
            title: {
                display: true,
                text: title,
                color: C.muted,
                font: { family: "'Inter', sans-serif", size: 11, weight: "500" },
                padding: { bottom: 10 }
            }
        },
        scales: {
            x: {
                grid: { color: C.border, drawBorder: false },
                ticks: {
                    color: C.muted,
                    font: { family: "'JetBrains Mono', monospace", size: 10 }
                },
                border: { color: C.border }
            },
            y: {
                grid: { display: false },
                ticks: {
                    color: C.text,
                    font: { family: "'JetBrains Mono', monospace", size: 10 }
                },
                border: { display: false }
            }
        }
    };
}

function baseDoughnutOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        cutout: "65%",
        plugins: {
            legend: {
                display: true,
                position: "bottom",
                labels: {
                    color: C.muted,
                    font: { family: "'Inter', sans-serif", size: 10 },
                    padding: 10,
                    boxWidth: 10
                }
            },
            title: {
                display: true,
                text: title,
                color: C.muted,
                font: { family: "'Inter', sans-serif", size: 11, weight: "500" },
                padding: { bottom: 10 }
            }
        }
    };
}

function baseLineOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                display: true,
                position: "bottom",
                labels: {
                    color: C.muted,
                    font: { family: "'Inter', sans-serif", size: 10 },
                    padding: 10,
                    boxWidth: 10
                }
            },
            title: {
                display: true,
                text: title,
                color: C.muted,
                font: { family: "'Inter', sans-serif", size: 11, weight: "500" },
                padding: { bottom: 10 }
            }
        },
        scales: {
            x: {
                grid: { color: C.border, drawBorder: false },
                ticks: {
                    color: C.muted,
                    font: { family: "'JetBrains Mono', monospace", size: 10 }
                },
                border: { color: C.border }
            },
            y: {
                grid: { color: C.border, drawBorder: false },
                ticks: {
                    color: C.muted,
                    font: { family: "'JetBrains Mono', monospace", size: 10 }
                },
                border: { display: false },
                min: 0,
                max: 100
            }
        }
    };
}

// ── Overview Page ──────────────────────────────────────
if (onIndex) {
    const ruleIds      = indexData.rule_metrics.map(r => r.rule_id);
    const passedCounts = indexData.rule_metrics.map(r => r.passed);
    const failedCounts = indexData.rule_metrics.map(r => r.failed);
    const fpCounts     = indexData.rule_metrics.map(r => r.fp);

    new Chart(document.getElementById("ruleResultChart"), {
        type: "bar",
        data: {
            labels: ruleIds,
            datasets: [
                {
                    label: "PASS",
                    data: passedCounts,
                    backgroundColor: C.green,
                    borderRadius: 1,
                    barThickness: 12
                },
                {
                    label: "FAIL",
                    data: failedCounts,
                    backgroundColor: C.red,
                    borderRadius: 1,
                    barThickness: 12
                },
                {
                    label: "FP",
                    data: fpCounts,
                    backgroundColor: C.yellow,
                    borderRadius: 1,
                    barThickness: 12
                }
            ]
        },
        options: {
            ...baseBarOptions("Results by Rule"),
            plugins: {
                ...baseBarOptions("Results by Rule").plugins,
                legend: {
                    display: true,
                    position: "bottom",
                    labels: {
                        color: C.muted,
                        font: { family: "'Inter', sans-serif", size: 10 },
                        padding: 10,
                        boxWidth: 10
                    }
                }
            }
        }
    });

    new Chart(document.getElementById("overallResultChart"), {
        type: "doughnut",
        data: {
            labels: ["PASS", "FAIL", "FP"],
            datasets: [{
                data: [
                    indexData.overall.passed,
                    indexData.overall.failed,
                    indexData.overall.fp
                ],
                backgroundColor: [C.green, C.red, C.yellow],
                borderWidth: 0
            }]
        },
        options: baseDoughnutOptions("Overall Results")
    });

    new Chart(document.getElementById("qualityChart"), {
        type: "bar",
        data: {
            labels: indexData.rule_metrics.map(r => r.rule_id),
            datasets: [{
                data: indexData.rule_metrics.map(r => r.quality_score),
                backgroundColor: indexData.rule_metrics.map(r => {
                    if (r.quality_score >= 70) return C.green;
                    if (r.quality_score >= 40) return C.yellow;
                    return C.red;
                }),
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Quality Score per Rule")
    });
}

// ── Metrics Page ───────────────────────────────────────
if (onMetrics) {
    const ruleIds        = metricsData.rule_metrics.map(r => r.rule_id);
    const detectionRates = metricsData.rule_metrics.map(r => r.detection_rate);
    const fpRates        = metricsData.rule_metrics.map(r => r.fp_rate);
    const qualityScores  = metricsData.rule_metrics.map(r => r.quality_score);

    new Chart(document.getElementById("detectionRateChart"), {
        type: "bar",
        data: {
            labels: ruleIds,
            datasets: [{
                label: "Detection Rate %",
                data: detectionRates,
                backgroundColor: C.blue,
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Detection Rate per Rule")
    });

    new Chart(document.getElementById("fpRateChart"), {
        type: "bar",
        data: {
            labels: ruleIds,
            datasets: [{
                label: "FP Rate %",
                data: fpRates,
                backgroundColor: C.yellow,
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("False Positive Rate per Rule")
    });

    new Chart(document.getElementById("qualityScoreChart"), {
        type: "bar",
        data: {
            labels: ruleIds,
            datasets: [{
                label: "Quality Score",
                data: qualityScores,
                backgroundColor: qualityScores.map(s => {
                    if (s >= 70) return C.green;
                    if (s >= 40) return C.yellow;
                    return C.red;
                }),
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Quality Score per Rule")
    });
}

// ── History Page ───────────────────────────────────────
if (onHistory) {
    const runs = historyData.slice().reverse();
    const labels         = runs.map(r => `Run ${r.id}`);
    const detectionRates = runs.map(r => r.detection_rate);
    const fpRates        = runs.map(r => r.fp_rate);
    const qualityScores  = runs.map(r => r.overall_quality_score);

    new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "Detection Rate %",
                    data: detectionRates,
                    borderColor: C.green,
                    backgroundColor: "transparent",
                    tension: 0.3,
                    pointBackgroundColor: C.green,
                    pointRadius: 4
                },
                {
                    label: "FP Rate %",
                    data: fpRates,
                    borderColor: C.yellow,
                    backgroundColor: "transparent",
                    tension: 0.3,
                    pointBackgroundColor: C.yellow,
                    pointRadius: 4
                },
                {
                    label: "Quality Score",
                    data: qualityScores,
                    borderColor: C.blue,
                    backgroundColor: "transparent",
                    tension: 0.3,
                    pointBackgroundColor: C.blue,
                    pointRadius: 4
                }
            ]
        },
        options: baseLineOptions("Detection Performance Over Time")
    });
}

// ── Quality Bar Fill ───────────────────────────────────
document.querySelectorAll(".quality-fill").forEach(el => {
    const score = parseFloat(el.dataset.score || "0");
    el.style.width = score + "%";
    if (score < 40)      el.classList.add("low");
    else if (score < 70) el.classList.add("medium");
});