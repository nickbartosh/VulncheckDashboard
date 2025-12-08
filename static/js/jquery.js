// jQuery-based initializer for charts (vuln pie chart)
// Expects global `window.VULNS_BY_SEVERITY` to be defined before this script runs.
(function ($) {
    'use strict';

    function buildPieChart(ctx, vulnsBySeverity) {
        // Severity order and colors (should match dashboard expectations)
        const severityOrder = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
        const colorsMap = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#e67e22',
            'MEDIUM': '#f1c40f',
            'LOW': '#2ecc71',
            'UNKNOWN': '#95a5a6'
        };

        const labels = [];
        const data = [];
        const bg = [];

        severityOrder.forEach(function(s){
            const count = vulnsBySeverity && vulnsBySeverity[s] ? vulnsBySeverity[s] : 0;
            if (count > 0) {
                labels.push(s);
                data.push(count);
                bg.push(colorsMap[s] || '#bdc3c7');
            }
        });

        if (labels.length === 0) {
            labels.push('None');
            data.push(1);
            bg.push('#ecf0f1');
        }

        return new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: bg
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }

    $(function () {
        try {
            var vulns = window.VULNS_BY_SEVERITY || {};
            console.log('Vulns by severity data:', vulns);
            var canvas = document.getElementById('vulnPieChart');
            if (!canvas) return;
            var ctx = canvas.getContext('2d');
            if (typeof Chart === 'undefined') {
                console.warn('Chart.js not loaded — pie chart cannot be rendered');
                return;
            }
            buildPieChart(ctx, vulns);
        } catch (e) {
            // Fail silently but log to console for debugging
            console.error('Error initializing vuln pie chart', e);
        }
    });

})(window.jQuery || window.$ || function(){ return; });
