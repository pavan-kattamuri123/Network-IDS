const canvas = document.getElementById('attackChart');
const placeholder = document.getElementById('chartPlaceholder');

// If no counts, show the placeholder and skip chart initialization
if (!counts || counts.length === 0) {
    if (placeholder) placeholder.style.display = 'flex';
} else {
    if (placeholder) placeholder.style.display = 'none';
    const ctx = canvas.getContext('2d');

    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                label: 'Attack Distribution',
                data: counts,
                backgroundColor: [
                    '#3498db',
                    '#e74c3c',
                    '#f1c40f',
                    '#2ecc71',
                    '#9b59b6'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}
