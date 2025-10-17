"""
Teste de criação automática de diretório logs/
"""
import os
import shutil
from monitoramento import NetworkMonitor
from datetime import datetime

print('🧪 TESTE: Criação automática de diretório')
print('')

# Remove diretório logs se existir
if os.path.exists('logs'):
    shutil.rmtree('logs')
    print('  ✅ Removido diretório logs/ existente')

print('  ✅ Estado inicial: logs/ NÃO existe')
print('')

# Criar monitor
monitor = NetworkMonitor(monitor_id='test', wifi_ssid='TestWiFi')
print(f'  ✅ Monitor criado com arquivo: {monitor.anomaly_file}')
print('')

# Salvar anomalia (deve criar diretório automaticamente)
anomaly_data = {
    'start_time': datetime.now(),
    'end_time': datetime.now(),
    'duration_seconds': 10.5,
    'avg_latency': 150.0,
    'min_latency': 120.0,
    'max_latency': 180.0,
    'pings_affected': 5,
    'start_ping_number': 1,
    'detection_method': 'threshold',
    'baseline_avg': 50.0,
    'baseline_min': 45.0,
    'baseline_max': 55.0,
    'increase_percent': 200.0
}
monitor.save_anomaly(anomaly_data)
print(f'  ✅ save_anomaly() executado')
print('')

# Verificar criação
print(f'  ✅ Diretório logs/ existe agora? {os.path.exists("logs")}')
print(f'  ✅ Arquivo existe? {os.path.exists(monitor.anomaly_file)}')
print('')

# Ler arquivo
if os.path.exists(monitor.anomaly_file):
    print(f'  📄 Conteúdo do arquivo:')
    with open(monitor.anomaly_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        print(f'    - Total de linhas: {len(lines)}')
        print(f'    - Header: {lines[0].strip()}')
        if len(lines) > 1:
            print(f'    - Primeira anomalia salva: {lines[1].strip()}')
else:
    print('  ❌ ERRO: Arquivo não foi criado!')
