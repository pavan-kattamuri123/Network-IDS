const canvas = document.getElementById('attackChart');
const placeholder = document.getElementById('chartPlaceholder');

if (!counts || counts.length === 0) {
    if (placeholder) placeholder.style.display = 'flex';
} else {
    if (placeholder) placeholder.style.display = 'none';
    const ctx = canvas.getContext('2d');

    new Chart(ctx, {
        type: 'pie', // Normal Pie Chart
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#3b82f6', // Blue
                    '#10b981', // Emerald
                    '#f59e0b', // Amber
                    '#ef4444', // Red
                    '#8b5cf6', // Violet
                    '#ec4899', // Pink
                    '#64748b'  // Slate
                ],
                borderColor: '#0f172a',
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        usePointStyle: true,
                        padding: 20,
                        font: { family: 'Inter', size: 12 }
                    }
                },
                tooltip: {
                    backgroundColor: '#1e293b',
                    padding: 12,
                    cornerRadius: 8,
                    titleFont: { family: 'Inter', size: 13 },
                    bodyFont: { family: 'Inter', size: 12 }
                }
            }
        }
    });
}
