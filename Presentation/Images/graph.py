import matplotlib.pyplot as plt

categories = ['System Intrusion', 'Social Engineering', 'Basic Web\nApplication Attacks', 'Miscellaneous Errors', 'Privilege Misuse']
values = [61, 17, 10, 8, 3]
colors = ['#1baf7a', '#2a78d6', '#eda100', '#e34948', '#4a3aa7']

y = range(len(categories))

fig, ax = plt.subplots(figsize=(8, 4.5), dpi=200)

bars = ax.barh(list(y), values, height=0.55, color=colors)

for b, v in zip(bars, values):
    ax.text(v + 0.8, b.get_y() + b.get_height()/2, f'{v}%', va='center', fontsize=10, color='#333333')

ax.set_yticks(list(y))
ax.set_yticklabels(categories, fontsize=11)
ax.invert_yaxis()
ax.set_xlabel('Percentuale delle breach (2026 DBIR, dataset 2025)', fontsize=10)
ax.set_xlim(0, 68)
ax.set_title('Pattern di breach (Verizon DBIR 2026)', fontsize=13, weight='bold', pad=15)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.grid(axis='x', color='#e1e0d9', linewidth=0.8, zorder=0)
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig('/home/fabio/dbir_breach_patterns.png', dpi=200, bbox_inches='tight', facecolor='white')
print("done")
