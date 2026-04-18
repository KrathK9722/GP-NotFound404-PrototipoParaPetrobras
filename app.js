const REQUIRED_PACKETS = 3;
const THREAT_RESPONSE_MS = 12000;
const TRANSFER_DURATION_MS = 2600;

const stages = [
  { id: 'node-glasses', name: 'Smart Glasses' },
  { id: 'node-edge', name: 'Edge Gateway' },
  { id: 'node-transport', name: 'TLS 1.3' },
  { id: 'node-ai', name: 'IA corporativa' },
  { id: 'node-data', name: 'Banco de dados em repouso + AES-256' },
  { id: 'node-response', name: 'Resposta ao operador' }
];

const threatCatalog = [
  {
    title: 'Tentativa de interceptação no caminho',
    detail: 'Um ponto não confiável tenta ler o pacote durante o tráfego entre o gateway e a IA.',
    context: 'transit',
    required: ['tls'],
    actions: {
      tls: 'TLS 1.3 protegeu o caminho, validou o certificado e manteve o canal criptografado.',
      siem: 'SIEM registrou a tentativa de interceptação nos logs da simulação.'
    }
  },
  {
    title: 'Token temporário em uso indevido',
    detail: 'Uma sessão externa tenta reutilizar o token do operador fora do dispositivo autorizado.',
    context: 'identity',
    required: ['iam'],
    actions: {
      iam: 'IAM revogou o token, invalidou a sessão e exigiu nova autenticação do operador.',
      siem: 'SIEM registrou usuário, horário e origem do uso indevido.'
    }
  },
  {
    title: 'Dado dos óculos sem permissão de compartilhamento',
    detail: 'O pacote saiu dos Smart Glasses, mas a política indica que esse dado não pode ser compartilhado.',
    context: 'glasses-egress',
    required: ['iam'],
    actions: {
      iam: 'IAM revogou a sessão do operador e bloqueou novos envios até uma nova autorização.',
      siem: 'SIEM registrou a tentativa de compartilhamento sem permissão.'
    }
  },
  {
    title: 'Uso indevido da resposta pelo usuário',
    detail: 'A resposta chegou ao operador, mas houve indício de uso fora da finalidade autorizada.',
    context: 'user-misuse',
    required: ['iam'],
    actions: {
      iam: 'IAM revogou a sessão ativa, removeu o acesso temporário e exigiu nova autorização.',
      siem: 'SIEM registrou o uso indevido da resposta nos logs.'
    }
  },
  {
    title: 'Dispositivo sem postura segura',
    detail: 'Os Smart Glasses aparecem com firmware desatualizado e risco de telemetria adulterada.',
    context: 'edge',
    required: ['edge'],
    actions: {
      edge: 'Edge Gateway isolou o dispositivo até que ele volte ao padrão corporativo.',
      siem: 'SIEM registrou o alerta de postura do dispositivo.'
    }
  },
  {
    title: 'Possível perda de dados sensíveis',
    detail: 'O fluxo indica que um dado sensível pode ter saído do limite esperado.',
    context: 'dlp-check',
    required: [],
    actions: {
      dlp: 'DLP verificou a movimentação dos dados e apontou risco de perda ou vazamento.',
      siem: 'SIEM registrou o alerta DLP nos logs da simulação.'
    }
  },
  {
    title: 'Banco de dados sem proteção em repouso',
    detail: 'A consulta encontrou dados armazenados sem proteção AES-256 em repouso.',
    context: 'db-rest',
    required: ['aes'],
    actions: {
      aes: 'AES-256 foi validado para proteger os dados parados no banco.',
      siem: 'SIEM registrou a falha de criptografia em repouso.'
    }
  }
];

const controlLabels = {
  tls: 'TLS',
  aes: 'AES',
  dlp: 'DLP',
  iam: 'IAM',
  edge: 'Edge Gateway',
  siem: 'SIEM'
};

const wrongActionMessages = {
  tls: 'TLS protege o caminho, mas não protege dados parados nem revoga sessão.',
  aes: 'AES protege dados em repouso, mas não protege o tráfego da rede.',
  dlp: 'DLP verifica perda ou vazamento, mas não autentica usuário nem criptografa o canal.',
  iam: 'IAM autentica, autoriza e revoga sessões, mas não criptografa dados.',
  edge: 'Edge Gateway valida a postura do dispositivo, mas não substitui TLS, AES, DLP ou SIEM.',
  siem: 'SIEM monitora e registra logs, mas não resolve o incidente sozinho.'
};

const state = {
  active: false,
  tokenIssued: false,
  tokenInGlasses: false,
  packetSequence: 0,
  completedPackets: 0,
  threatsDetected: 0,
  threatsBlocked: 0,
  failures: 0,
  keysRotated: false,
  controls: {
    auth: false,
    encryption: false,
    kms: false,
    dlp: false,
    siem: false
  },
  sessionRevoked: false,
  activeThreat: null,
  activeThreatPacketId: null,
  resolvedThreatActions: new Set(),
  activeTransfers: new Map(),
  contextualIncidents: new Set(),
  events: [],
  threatTimer: null,
  threatInterval: null,
  draggedElement: null
};

const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');
const simulationTabButton = document.querySelector('[data-tab="simulation"]');
const startFlowButton = document.getElementById('startFlow');
const startGameButton = document.getElementById('start-game');
const showHelpButton = document.getElementById('show-help');
const issueTokenButton = document.getElementById('issue-token');
const generateDataButton = document.getElementById('generate-data');
const tlsButton = document.getElementById('action-tls');
const aesButton = document.getElementById('action-aes');
const iamButton = document.getElementById('action-iam');
const edgeButton = document.getElementById('action-edge');
const finishButton = document.getElementById('finish-simulation');
const resetButton = document.getElementById('reset-simulation');
const clearLogsButton = document.getElementById('clear-logs');

const statusBadge = document.getElementById('status-badge');
const simStatus = document.getElementById('sim-status');
const packetsCount = document.getElementById('packets-count');
const threatsCount = document.getElementById('threats-count');
const failuresCount = document.getElementById('failures-count');
const tokenContainer = document.getElementById('token-container');
const dataContainer = document.getElementById('data-container');
const logConsole = document.getElementById('log-console');
const threatZone = document.getElementById('threat-zone');
const threatTitle = document.getElementById('threat-title');
const threatDetail = document.getElementById('threat-detail');
const threatAlert = document.getElementById('threat-alert');
const activeThreatName = document.getElementById('active-threat-name');
const requiredControls = document.getElementById('required-controls');
const liveProgress = document.getElementById('live-progress');
const liveControls = document.getElementById('live-controls');
const liveContainment = document.getElementById('live-containment');
const liveRating = document.getElementById('live-rating');

function switchTab(tabId) {
  tabButtons.forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === tabId);
  });

  tabContents.forEach((content) => {
    content.classList.toggle('active', content.id === tabId);
  });
}

function setStatus(status) {
  simStatus.textContent = status;
  simStatus.className = `status-indicator ${status.toLowerCase()}`;
  statusBadge.textContent = status;
}

function addLog(message, level = 'info') {
  const prefixes = {
    info: 'INFO',
    success: 'OK',
    warning: 'WARN',
    error: 'FAIL'
  };
  const timestamp = new Date().toLocaleTimeString('pt-BR');
  const entry = document.createElement('p');
  entry.className = `log-entry log-entry--${level}`;
  entry.textContent = `[${timestamp}] [${prefixes[level] || 'INFO'}] ${message}`;
  logConsole.appendChild(entry);
  logConsole.scrollTop = logConsole.scrollHeight;
}

function recordEvent(type, title, packetLabel = '-', detail = '') {
  state.events.push({
    type,
    title,
    packetLabel,
    detail,
    time: new Date().toLocaleTimeString('pt-BR')
  });
}

function setControl(control, value, reason) {
  state.controls[control] = value;
  if (reason) {
    addLog(reason, value ? 'success' : 'warning');
  }
  updateDashboard();
}

function updateDashboard() {
  const stats = getStats();
  packetsCount.textContent = `${state.completedPackets}/${REQUIRED_PACKETS}`;
  threatsCount.textContent = `${state.threatsBlocked}/${state.threatsDetected}`;
  failuresCount.textContent = state.failures;

  updateCheck('check-auth', state.controls.auth);
  updateCheck('check-encryption', state.controls.encryption);
  updateCheck('check-kms', state.controls.kms);
  updateCheck('check-dlp', state.controls.dlp);
  updateCheck('check-siem', state.controls.siem);

  generateDataButton.disabled = !state.active || state.sessionRevoked || !state.tokenInGlasses || state.packetSequence >= REQUIRED_PACKETS;
  issueTokenButton.disabled = !state.active || state.tokenIssued;
  const controlsDisabled = !state.active || !state.activeThreat;
  tlsButton.disabled = controlsDisabled;
  aesButton.disabled = controlsDisabled;
  iamButton.disabled = controlsDisabled;
  edgeButton.disabled = controlsDisabled;
  finishButton.disabled = !state.active;

  liveProgress.textContent = `${stats.progress}%`;
  liveControls.textContent = `${stats.controlsValid}/5`;
  liveContainment.textContent = `${stats.containmentRate}%`;
  liveRating.textContent = stats.rating;
}

function updateCheck(id, completed) {
  const element = document.getElementById(id);
  element.classList.toggle('completed', completed);
  element.querySelector('strong').textContent = completed ? 'validado' : 'pendente';
}

function resetMap() {
  tokenContainer.innerHTML = '';
  dataContainer.innerHTML = '';
  document.querySelectorAll('.packet').forEach((packet) => packet.remove());
  document.querySelectorAll('.architecture-node').forEach((node) => {
    node.classList.remove('node-complete', 'node-active', 'drop-valid', 'drop-invalid');
  });
}

function initializeSimulation() {
  stopThreats();
  clearTimeout(state.threatTimer);
  clearAllTransfers();
  Object.assign(state, {
    active: true,
    tokenIssued: false,
    tokenInGlasses: false,
    packetSequence: 0,
    completedPackets: 0,
    threatsDetected: 0,
    threatsBlocked: 0,
    failures: 0,
    keysRotated: false,
    sessionRevoked: false,
    activeThreat: null,
    activeThreatPacketId: null,
    resolvedThreatActions: new Set(),
    activeTransfers: new Map(),
    contextualIncidents: new Set(),
    events: [],
    threatTimer: null,
    threatInterval: null,
    draggedElement: null
  });
  state.controls = {
    auth: false,
    encryption: false,
    kms: false,
    dlp: false,
    siem: false
  };

  resetMap();
  hideThreat();
  logConsole.innerHTML = '';
  simulationTabButton.disabled = false;
  switchTab('simulation');
  setStatus('Ativo');
  addLog('Nós da NotFound404 iniciamos a simulação para o GrandPrix de Inovação 2026.', 'success');
  addLog('Tema: Cibersegurança e Ética Digital no uso de Smart Glasses com IA.', 'info');
  addLog('Roteiro: Smart Glasses > Edge > TLS > IA > Banco com AES > Resposta ao operador.', 'info');
  updateDashboard();
  startThreats();
}

function issueToken() {
  if (!state.active || state.tokenIssued) return;

  state.tokenIssued = true;
  generateDataButton.textContent = 'Gerar pacote de campo';
  const token = document.createElement('div');
  token.id = 'packet-token';
  token.className = 'packet packet--token';
  token.draggable = true;
  token.dataset.type = 'token';
  token.textContent = 'TOKEN-TURNO';
  tokenContainer.appendChild(token);
  setupDragEvents(token);
  addLog('IAM emitiu um token temporário para o operador.', 'success');
  updateDashboard();
}

function generateDataPacket() {
  if (!state.active || state.sessionRevoked || !state.tokenInGlasses || state.packetSequence >= REQUIRED_PACKETS) return;

  state.packetSequence += 1;
  const packet = document.createElement('div');
  packet.id = `packet-data-${state.packetSequence}`;
  packet.className = 'packet packet--data';
  packet.draggable = true;
  packet.dataset.type = 'data';
  packet.dataset.stage = '0';
  packet.dataset.label = `PKT-${state.packetSequence}`;
  packet.textContent = `PKT-${state.packetSequence}`;
  dataContainer.appendChild(packet);
  setupDragEvents(packet);
  markNodeActive(0);
  addLog(`${packet.dataset.label} foi gerado nos Smart Glasses com minimização de dados.`, 'success');
  updateDashboard();
}

function setupDragEvents(packet) {
  packet.addEventListener('dragstart', (event) => {
    if (!state.active || state.sessionRevoked || packet.dataset.inTransit === 'true') {
      event.preventDefault();
      if (state.sessionRevoked) {
        addLog('Sessão IAM revogada: novas movimentações do usuário foram bloqueadas.', 'warning');
      }
      return;
    }
    state.draggedElement = packet;
    event.dataTransfer.effectAllowed = 'move';
  });

  packet.addEventListener('dragend', () => {
    state.draggedElement = null;
    document.querySelectorAll('.drop-node').forEach((node) => {
      node.classList.remove('drop-valid', 'drop-invalid');
    });
  });
}

function setupDropZones() {
  document.querySelectorAll('.drop-node').forEach((node) => {
    node.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (!state.draggedElement) return;
      node.classList.toggle('drop-valid', canDropOnNode(state.draggedElement, node));
      node.classList.toggle('drop-invalid', !canDropOnNode(state.draggedElement, node));
    });

    node.addEventListener('dragleave', () => {
      node.classList.remove('drop-valid', 'drop-invalid');
    });

    node.addEventListener('drop', (event) => {
      event.preventDefault();
      node.classList.remove('drop-valid', 'drop-invalid');
      handleDrop(node);
    });
  });
}

function canDropOnNode(packet, node) {
  if (packet.dataset.type === 'token') {
    return node.id === 'node-glasses';
  }

  if (packet.dataset.type === 'data') {
    const currentStage = Number(packet.dataset.stage);
    const targetStage = Number(node.dataset.stage);
    return targetStage === currentStage + 1;
  }

  return false;
}

function handleDrop(node) {
  const packet = state.draggedElement;
  if (!packet || !canDropOnNode(packet, node)) {
    addLog('Transferência recusada: siga a ordem do fluxo.', 'error');
    return;
  }

  if (packet.dataset.type === 'token') {
    node.appendChild(packet);
    packet.draggable = false;
    state.tokenInGlasses = true;
    setControl('auth', true, 'Token validado nos Smart Glasses. Coleta liberada.');
    updateDashboard();
    return;
  }

  if (state.activeThreat) {
    addLog(`${packet.dataset.label} pausado: trate o incidente ativo antes de continuar.`, 'warning');
    updateDashboard();
    return;
  }

  beginTransfer(packet, node);
}

function beginTransfer(packet, node) {
  const targetStage = Number(node.dataset.stage);
  const currentStage = Number(packet.dataset.stage);
  const sourceName = stages[currentStage]?.name || 'origem';
  const targetName = stages[targetStage]?.name || 'destino';

  packet.draggable = false;
  packet.dataset.inTransit = 'true';
  packet.dataset.targetStage = String(targetStage);
  packet.textContent = packet.dataset.unauthorized === 'true'
    ? `${packet.dataset.label} SEM PERMISSÃO`
    : `${packet.dataset.label} EM TRÂNSITO`;
  packet.classList.add('packet--transit');
  packet.classList.toggle('packet--unauthorized', packet.dataset.unauthorized === 'true');

  const transfer = {
    packet,
    node,
    targetStage,
    timeoutId: null
  };
  state.activeTransfers.set(packet.id, transfer);

  addLog(`${packet.dataset.label} saiu de ${sourceName} para ${targetName}. Janela de trânsito aberta.`, 'info');

  transfer.timeoutId = window.setTimeout(() => completeTransferWhenReady(packet.id), TRANSFER_DURATION_MS);

  if (shouldOpenTransitIncident(currentStage, targetStage)) {
    window.setTimeout(() => {
      if (state.activeTransfers.has(packet.id) && !state.activeThreat) {
        showThreat('transit', packet);
      }
    }, 700);
  }

  if (currentStage === 0 && targetStage === 1 && !state.contextualIncidents.has('glasses-egress')) {
    state.contextualIncidents.add('glasses-egress');
    window.setTimeout(() => {
      if (state.activeTransfers.has(packet.id) && !state.activeThreat) {
        showThreat('glasses-egress', packet);
      }
    }, 550);
  }

  if (packet.dataset.unauthorized === 'true') {
    window.setTimeout(() => {
      if (state.activeTransfers.has(packet.id) && !state.activeThreat) {
        showThreat('glasses-egress', packet);
      }
    }, 550);
  }

  updateDashboard();
}

function completeTransfer(packetId) {
  const transfer = state.activeTransfers.get(packetId);
  if (!transfer) return;

  const { packet, node, targetStage } = transfer;
  state.activeTransfers.delete(packetId);

  packet.dataset.inTransit = 'false';
  packet.dataset.stage = String(targetStage);
  packet.draggable = true;
  packet.textContent = packet.dataset.unauthorized === 'true'
    ? `${packet.dataset.label} SEM PERMISSÃO`
    : packet.dataset.label;
  packet.classList.remove('packet--transit');
  packet.classList.toggle('packet--unauthorized', packet.dataset.unauthorized === 'true');

  movePacket(packet, node, targetStage);
}

function completeTransferWhenReady(packetId) {
  const transfer = state.activeTransfers.get(packetId);
  if (!transfer) return;

  if (state.activeThreat) {
    addLog(`${transfer.packet.dataset.label} aguardando tratamento do incidente antes de avançar.`, 'warning');
    transfer.timeoutId = window.setTimeout(() => completeTransferWhenReady(packetId), 900);
    return;
  }

  completeTransfer(packetId);
}

function movePacket(packet, node, targetStage = Number(node.dataset.stage)) {
  packet.dataset.stage = String(targetStage);
  node.appendChild(packet);
  markNodeComplete(targetStage);

  const stageName = stages[targetStage].name;
  addLog(`${packet.dataset.label} chegou em ${stageName}.`, 'info');

  if (targetStage === 2) {
    addLog('TLS protege esta etapa caso ocorra interceptação no caminho.', 'info');
  }

  if (targetStage === 4) {
    addLog('O pacote está parado no banco. Aqui entra a proteção AES em repouso.', 'info');
  }

  if (targetStage === 4 && !state.activeThreat) {
    window.setTimeout(() => showThreat('db-rest', packet), 500);
  }

  if (targetStage === 5) {
    setControl('dlp', true, `DLP verificou perda ou vazamento no ${packet.dataset.label}.`);
    setControl('siem', true, `SIEM registrou a trilha do ${packet.dataset.label}.`);
    packet.draggable = false;
    packet.classList.add('packet--complete');
    state.completedPackets += 1;
    addLog(`${packet.dataset.label} retornou ao operador com rastreabilidade.`, 'success');
    if (state.completedPackets === REQUIRED_PACKETS && !state.contextualIncidents.has('user-misuse')) {
      state.contextualIncidents.add('user-misuse');
      window.setTimeout(() => {
        if (!state.activeThreat) {
          showThreat('user-misuse', packet);
        }
      }, 600);
      updateDashboard();
      return;
    }
    checkVictoryCondition();
  } else {
    markNodeActive(targetStage + 1);
  }

  updateDashboard();
}

function shouldOpenTransitIncident(currentStage, targetStage) {
  const transferKey = `${currentStage}-${targetStage}`;
  const isMiddlePath = currentStage >= 1 && targetStage <= 3;

  if (!isMiddlePath || state.contextualIncidents.has(`transit-${transferKey}`)) {
    return false;
  }

  state.contextualIncidents.add(`transit-${transferKey}`);
  return true;
}

function markNodeComplete(stage) {
  const node = document.getElementById(stages[stage].id);
  node.classList.add('node-complete');
  node.classList.remove('node-active');
}

function markNodeActive(stage) {
  if (!stages[stage]) return;
  document.querySelectorAll('.architecture-node').forEach((node) => node.classList.remove('node-active'));
  document.getElementById(stages[stage].id).classList.add('node-active');
}

function startThreats() {
  state.threatInterval = window.setInterval(() => {
    if (state.active && !state.activeThreat) {
      triggerContextualIncident();
    }
  }, 5000);
}

function stopThreats() {
  if (state.threatInterval) {
    clearInterval(state.threatInterval);
    state.threatInterval = null;
  }
}

function triggerContextualIncident() {
  const transfer = Array.from(state.activeTransfers.values()).find((item) => {
    const currentStage = Number(item.packet.dataset.stage);
    return shouldOpenTransitIncident(currentStage, item.targetStage);
  });

  if (transfer) {
    if (!state.activeThreat) {
      showThreat('transit', transfer.packet);
    }
    return;
  }

  const packets = Array.from(document.querySelectorAll('.packet--data'));
  const packetAtEdge = packets.find((packet) => Number(packet.dataset.stage) === 1);
  const packetAtDb = packets.find((packet) => Number(packet.dataset.stage) === 4);

  if (packetAtEdge && !state.contextualIncidents.has('edge-auto')) {
    state.contextualIncidents.add('edge-auto');
    showThreat('edge', packetAtEdge);
    return;
  }

  if (packetAtDb && !state.contextualIncidents.has('db-rest-auto')) {
    state.contextualIncidents.add('db-rest-auto');
    showThreat('db-rest', packetAtDb);
    return;
  }

  if (!state.contextualIncidents.has('dlp-log-reminder')) {
    state.contextualIncidents.add('dlp-log-reminder');
    addLog('DLP e SIEM atuam em segundo plano: verificam perdas, avisam incidentes e registram logs.', 'info');
  }
}

function showThreat(context, packet) {
  if (state.activeThreat) return;

  const candidates = threatCatalog.filter((threat) => threat.context === context);
  const threat = candidates[Math.floor(Math.random() * candidates.length)];
  if (!threat) return;

  state.activeThreat = threat;
  state.activeThreatPacketId = packet?.id || null;
  state.resolvedThreatActions = new Set();
  state.keysRotated = false;
  state.threatsDetected += 1;

  threatTitle.textContent = threat.title;
  threatDetail.textContent = packet?.dataset?.label
    ? `${threat.detail} Pacote: ${packet.dataset.label}.`
    : threat.detail;
  activeThreatName.textContent = threat.title;
  requiredControls.textContent = threat.required.length > 0
    ? `Ação manual necessária: ${threat.required.map((control) => controlLabels[control]).join(', ')}`
    : 'DLP e SIEM atuam automaticamente neste incidente';
  threatAlert.hidden = false;
  threatZone.classList.add('visible');
  threatZone.style.left = `${15 + Math.random() * 60}%`;
  threatZone.style.top = `${18 + Math.random() * 55}%`;

  addLog(`Incidente detectado: ${threat.title}. ${threat.detail}`, 'warning');
  recordEvent('incident', threat.title, packet?.dataset?.label || '-', threat.detail);
  runAutomaticMonitoring(threat);
  if (threat.required.length > 0) {
    addLog(`Ação esperada: ${threat.required.map((control) => controlLabels[control]).join(' + ')}.`, 'info');
  } else {
    addLog('Incidente tratado por verificação automática do DLP e registro no SIEM.', 'info');
    resolveThreatIfComplete();
  }
  updateDashboard();

  if (!state.activeThreat) return;

  state.threatTimer = window.setTimeout(() => {
    if (!state.activeThreat) return;
    state.failures += 1;
    const missing = getMissingThreatControls().map((control) => controlLabels[control]).join(', ');
    addLog(`Falha de resposta: ${state.activeThreat.title} não foi resolvido. Pendência: ${missing}.`, 'error');
    if (state.activeThreat.context === 'transit') {
      failActiveTransfer();
    }
    if (state.activeThreat.context === 'glasses-egress') {
      recordEvent('unauthorized-share', 'Tentativa de compartilhamento sem permissão', state.activeThreatPacketId ? document.getElementById(state.activeThreatPacketId)?.dataset?.label || '-' : '-', 'O pacote continuou no fluxo marcado como sem permissão.');
      markPacketAsUnauthorized();
    }
    hideThreat();
    resumeReadyTransfers();
    updateDashboard();
  }, THREAT_RESPONSE_MS);
}

function applyThreatControl(control) {
  if (!state.activeThreat) return;

  if (!state.activeThreat.required.includes(control)) {
    addLog(`${controlLabels[control]} não resolve este problema. ${wrongActionMessages[control]}`, 'warning');
    return;
  }

  if (state.resolvedThreatActions.has(control)) {
    addLog(`${controlLabels[control]} já foi aplicado neste evento.`, 'info');
    return;
  }

  state.resolvedThreatActions.add(control);
  addLog(state.activeThreat.actions[control], 'success');

  if (control === 'iam') state.controls.auth = true;
  if (control === 'tls') state.controls.encryption = true;
  if (control === 'aes') state.controls.kms = true;
  if (control === 'dlp') state.controls.dlp = true;
  if (control === 'siem') state.controls.siem = true;

  if (control === 'iam' && state.activeThreat.context === 'glasses-egress') {
    barInitialPacketByIam();
    return;
  }

  if (control === 'iam' && state.activeThreat.context === 'user-misuse') {
    revokeUserSessionForMisuse();
    return;
  }

  const missing = getMissingThreatControls();
  if (missing.length > 0) {
    addLog(`Ainda falta: ${missing.map((item) => controlLabels[item]).join(', ')}.`, 'info');
    updateDashboard();
    return;
  }

  resolveThreatIfComplete();
}

function runAutomaticMonitoring(threat) {
  if (!state.resolvedThreatActions.has('siem')) {
    state.resolvedThreatActions.add('siem');
    state.controls.siem = true;
    addLog(threat.actions.siem || 'SIEM registrou evidências do incidente.', 'success');
  }

  if (threat.actions.dlp && !state.resolvedThreatActions.has('dlp')) {
    state.resolvedThreatActions.add('dlp');
    state.controls.dlp = true;
    recordEvent('dlp-check', 'DLP verificou perda de dados', state.activeThreatPacketId ? document.getElementById(state.activeThreatPacketId)?.dataset?.label || '-' : '-', threat.actions.dlp);
    addLog(threat.actions.dlp, 'success');
  }
}

function resolveThreatIfComplete() {
  if (!state.activeThreat || getMissingThreatControls().length > 0) return;

  state.threatsBlocked += 1;
  const resolvedContext = state.activeThreat.context;
  const manualControls = state.activeThreat.required.map((item) => controlLabels[item]).join(' + ');
  const resolution = manualControls
    ? `Incidente tratado com o controle correto: ${manualControls}. SIEM registrou o evento automaticamente.`
    : 'Incidente tratado automaticamente por DLP e SIEM.';
  recordEvent('treated', 'Incidente tratado', state.activeThreatPacketId ? document.getElementById(state.activeThreatPacketId)?.dataset?.label || '-' : '-', `${state.activeThreat.title} tratado com ${manualControls || 'DLP/SIEM automático'}.`);
  addLog(resolution, 'success');
  clearTimeout(state.threatTimer);
  hideThreat();
  resumeReadyTransfers();
  updateDashboard();
  checkVictoryCondition();
}

function barInitialPacketByIam() {
  if (!state.activeThreat || getMissingThreatControls().length > 0) return;

  const transfer = findTransferForContext('glasses-egress');
  const packetFromAlert = state.activeThreatPacketId
    ? document.getElementById(state.activeThreatPacketId)
    : null;
  state.threatsBlocked += 1;

  if (transfer) {
    clearTimeout(transfer.timeoutId);
    const { packet } = transfer;
    state.activeTransfers.delete(packet.id);
    packet.dataset.inTransit = 'false';
    packet.dataset.stage = '5';
    packet.textContent = `${packet.dataset.label} BARRADO`;
    packet.classList.remove('packet--transit');
    packet.classList.add('packet--barred');
    packet.draggable = false;
    document.getElementById('node-response').appendChild(packet);
    state.completedPackets += 1;
    recordEvent('barred', 'Pacote barrado por IAM', packet.dataset.label, 'O dado não podia ser compartilhado fora dos óculos.');
    addLog(`${packet.dataset.label} foi barrado por IAM no início do fluxo e encerrado com segurança.`, 'success');
  } else if (packetFromAlert && !packetFromAlert.classList.contains('packet--complete')) {
    const pendingTransfer = state.activeTransfers.get(packetFromAlert.id);
    if (pendingTransfer) {
      clearTimeout(pendingTransfer.timeoutId);
      state.activeTransfers.delete(packetFromAlert.id);
    }
    packetFromAlert.dataset.unauthorized = 'false';
    packetFromAlert.dataset.stage = '5';
    packetFromAlert.textContent = `${packetFromAlert.dataset.label} BARRADO`;
    packetFromAlert.classList.remove('packet--transit', 'packet--unauthorized');
    packetFromAlert.classList.add('packet--barred');
    packetFromAlert.draggable = false;
    document.getElementById('node-response').appendChild(packetFromAlert);
    state.completedPackets += 1;
    recordEvent('barred', 'Pacote barrado por IAM', packetFromAlert.dataset.label, 'O dado sem permissão foi retirado do fluxo.');
    addLog(`${packetFromAlert.dataset.label} foi barrado por IAM e retirado do fluxo.`, 'success');
  }

  clearTimeout(state.threatTimer);
  hideThreat();
  updateDashboard();
  checkVictoryCondition();
}

function revokeUserSessionForMisuse() {
  if (!state.activeThreat || getMissingThreatControls().length > 0) return;

  const misusedPacket = state.activeThreatPacketId
    ? document.getElementById(state.activeThreatPacketId)
    : null;

  state.sessionRevoked = true;
  state.threatsBlocked += 1;
  recordEvent('misuse', 'Uso indevido da resposta', misusedPacket?.dataset?.label || '-', 'O usuário usou a resposta fora da finalidade autorizada.');
  recordEvent('revoked', 'Sessão IAM revogada', misusedPacket?.dataset?.label || '-', 'Os óculos foram desligados e novos envios foram bloqueados.');

  dataContainer.innerHTML = '';
  generateDataButton.textContent = 'Óculos desligados';

  state.activeTransfers.forEach((transfer) => {
    clearTimeout(transfer.timeoutId);
    const { packet } = transfer;
    packet.dataset.inTransit = 'false';
    packet.textContent = `${packet.dataset.label} BARRADO`;
    packet.classList.remove('packet--transit', 'packet--unauthorized');
    packet.classList.add('packet--barred');
    packet.draggable = false;
    document.getElementById('node-response').appendChild(packet);
    recordEvent('barred', 'Dado pendente barrado', packet.dataset.label, 'O pacote estava em trânsito quando a sessão foi revogada.');
  });
  state.activeTransfers.clear();

  document.querySelectorAll('.packet--data:not(.packet--complete):not(.packet--barred)').forEach((packet) => {
    packet.draggable = false;
    packet.dataset.inTransit = 'false';
    packet.dataset.unauthorized = 'false';
    packet.classList.remove('packet--transit', 'packet--unauthorized');
    packet.classList.add('packet--barred');
    packet.textContent = `${packet.dataset.label} BARRADO`;
    recordEvent('barred', 'Dado pendente barrado', packet.dataset.label, 'O pacote foi barrado após revogação total do IAM.');
  });

  clearTimeout(state.threatTimer);
  hideThreat();
  setSimulationStatusAfterRevocation();
  addLog('Sessão IAM revogada por uso indevido da resposta. Óculos desligados e todos os dados pendentes foram barrados.', 'success');
  updateDashboard();
  checkVictoryCondition();
}

function markPacketAsUnauthorized() {
  const packet = state.activeThreatPacketId
    ? document.getElementById(state.activeThreatPacketId)
    : null;

  if (!packet || packet.classList.contains('packet--barred') || packet.classList.contains('packet--complete')) {
    return;
  }

  packet.dataset.unauthorized = 'true';
  packet.classList.add('packet--unauthorized');
  packet.textContent = `${packet.dataset.label} SEM PERMISSÃO`;
  recordEvent('unauthorized-share', 'Dado sem permissão continuou no fluxo', packet.dataset.label, 'O IAM não foi revogado no momento do alerta.');
  addLog(`${packet.dataset.label} continuou no fluxo, mas agora está marcado como dado sem permissão. O IAM será solicitado novamente no próximo setor.`, 'warning');
}

function setSimulationStatusAfterRevocation() {
  generateDataButton.disabled = true;
  issueTokenButton.disabled = true;
  setStatus('Revogado');
}

function failActiveTransfer() {
  const transfer = findTransferForContext('transit');
  if (!transfer) return;

  const { packet, timeoutId } = transfer;
  clearTimeout(timeoutId);
  packet.remove();
  state.activeTransfers.delete(packet.id);
  recordEvent('data-loss', 'Perda por interceptação', packet.dataset.label, 'O pacote foi descartado durante o trânsito.');
  addLog('Pacote interceptado durante o trânsito. A transmissão foi descartada.', 'error');
}

function findTransferForContext(context) {
  const transfers = Array.from(state.activeTransfers.values());

  if (context === 'glasses-egress') {
    return transfers.find((item) => Number(item.packet.dataset.stage) === 0 && item.targetStage === 1);
  }

  if (context === 'transit') {
    return transfers.find((item) => Number(item.packet.dataset.stage) >= 1 && item.targetStage <= 3);
  }

  return transfers[0];
}

function resumeReadyTransfers() {
  Array.from(state.activeTransfers.keys()).forEach((packetId) => {
    if (!state.activeThreat) {
      completeTransferWhenReady(packetId);
    }
  });
}

function clearAllTransfers() {
  state.activeTransfers.forEach((transfer) => clearTimeout(transfer.timeoutId));
  state.activeTransfers.clear();
}

function finishSimulation() {
  if (!state.active) return;

  clearTimeout(state.threatTimer);
  stopThreats();
  clearAllTransfers();

  if (state.activeThreat) {
    state.failures += 1;
    addLog(`Simulação encerrada com incidente ativo: ${state.activeThreat.title}.`, 'error');
    hideThreat();
  }

  state.active = false;
  setStatus('Encerrado');
  addLog('Simulação finalizada. Estatísticas consolidadas.', 'info');
  updateDashboard();
  showResultModal(false);
}

function hideThreat() {
  state.activeThreat = null;
  state.activeThreatPacketId = null;
  state.resolvedThreatActions = new Set();
  threatAlert.hidden = true;
  threatZone.classList.remove('visible');
  threatTitle.textContent = 'Incidente';
  threatDetail.textContent = 'Aguardando evento';
  requiredControls.textContent = 'Aguardando classificação';
}

function getMissingThreatControls() {
  if (!state.activeThreat) return [];
  return state.activeThreat.required.filter((control) => !state.resolvedThreatActions.has(control));
}

function getStats() {
  const controlsValid = Object.values(state.controls).filter(Boolean).length;
  const progress = Math.round((state.completedPackets / REQUIRED_PACKETS) * 100);
  const containmentRate = state.threatsDetected
    ? Math.round((state.threatsBlocked / state.threatsDetected) * 100)
    : 0;
  const dataLossCount = state.events.filter((event) => event.type === 'data-loss').length;
  const unauthorizedCount = state.events.filter((event) => event.type === 'unauthorized-share').length;
  const misuseCount = state.events.filter((event) => event.type === 'misuse').length;
  const barredCount = state.events.filter((event) => event.type === 'barred').length;
  const controlRate = Math.round((controlsValid / 5) * 100);
  const operationalScore = Math.max(
    0,
    Math.round((progress * 0.4) + (controlRate * 0.35) + (containmentRate * 0.25) - (state.failures * 15))
  );

  let rating = 'Crítico';
  if (operationalScore >= 90) rating = 'Aprovado';
  else if (operationalScore >= 70) rating = 'Adequado';
  else if (operationalScore >= 45) rating = 'Parcial';

  return {
    controlsValid,
    progress,
    containmentRate,
    dataLossCount,
    unauthorizedCount,
    misuseCount,
    barredCount,
    controlRate,
    operationalScore,
    rating
  };
}

function getControlRows() {
  const labels = {
    auth: 'Autenticação',
    encryption: 'TLS em trânsito',
    kms: 'AES em repouso',
    dlp: 'DLP',
    siem: 'SIEM'
  };

  return Object.entries(state.controls).map(([key, value]) => `
    <div class="stat-row">
      <span>${labels[key]}</span>
      <strong>${value ? 'Validado' : 'Pendente'}</strong>
    </div>
  `).join('');
}

function getEventRows() {
  if (state.events.length === 0) {
    return '<p class="empty-events">Nenhuma ocorrência registrada.</p>';
  }

  const typeLabels = {
    incident: 'Incidente',
    treated: 'Tratado',
    'data-loss': 'Perda de dados',
    'unauthorized-share': 'Compartilhamento indevido',
    misuse: 'Uso indevido',
    revoked: 'IAM revogado',
    barred: 'Barrado',
    'dlp-check': 'DLP'
  };

  return state.events.map((event) => `
    <div class="event-row event-row--${event.type}">
      <div>
        <strong>${typeLabels[event.type] || event.type}</strong>
        <span>${event.title}</span>
        <small>${event.detail}</small>
      </div>
      <em>${event.packetLabel} | ${event.time}</em>
    </div>
  `).join('');
}

function checkVictoryCondition() {
  const allControlsValid = Object.values(state.controls).every(Boolean);
  const threatsOk = state.threatsDetected > 0 && state.threatsBlocked === state.threatsDetected;

  if (state.completedPackets === REQUIRED_PACKETS && allControlsValid && threatsOk && state.failures === 0) {
    state.active = false;
    stopThreats();
    hideThreat();
    setStatus('Aprovado');
    addLog('Arquitetura validada: pacotes concluídos, controles ativos e nenhuma falha aberta.', 'success');
    updateDashboard();
    showResultModal(true);
  }
}

function showResultModal(success) {
  const stats = getStats();
  const modal = document.createElement('div');
  modal.className = 'result-modal';
  modal.innerHTML = `
    <div class="result-card">
      <p class="section-kicker">${success ? 'Aprovado' : 'Estatísticas'}</p>
      <h2>${success ? 'Arquitetura validada' : 'Simulação finalizada'}</h2>
      <div class="score-card">
        <span>Score operacional</span>
        <strong>${stats.operationalScore}%</strong>
        <em>${stats.rating}</em>
      </div>
      <div class="stats-grid">
        <div><span>Pacotes seguros</span><strong>${state.completedPackets}/${REQUIRED_PACKETS}</strong></div>
        <div><span>Progresso</span><strong>${stats.progress}%</strong></div>
        <div><span>Incidentes tratados</span><strong>${state.threatsBlocked}/${state.threatsDetected}</strong></div>
        <div><span>Taxa de tratamento</span><strong>${stats.containmentRate}%</strong></div>
        <div><span>Controles</span><strong>${stats.controlsValid}/5</strong></div>
        <div><span>Falhas</span><strong>${state.failures}</strong></div>
        <div><span>Perdas por interceptação</span><strong>${stats.dataLossCount}</strong></div>
        <div><span>Compartilhamentos indevidos</span><strong>${stats.unauthorizedCount}</strong></div>
        <div><span>Uso indevido pelo usuário</span><strong>${stats.misuseCount}</strong></div>
        <div><span>Pacotes barrados</span><strong>${stats.barredCount}</strong></div>
      </div>
      <h3>Controles de segurança</h3>
      <div class="stat-list">${getControlRows()}</div>
      <h3>O que aconteceu no processo</h3>
      <div class="event-list">${getEventRows()}</div>
      <button type="button" id="close-result">Continuar analisando</button>
    </div>
  `;
  document.body.appendChild(modal);
  document.getElementById('close-result').addEventListener('click', () => modal.remove());
}

tabButtons.forEach((button) => {
  button.addEventListener('click', () => {
    if (button.disabled) return;
    switchTab(button.dataset.tab);
  });
});

startFlowButton.addEventListener('click', () => switchTab('about'));
startGameButton.addEventListener('click', initializeSimulation);
showHelpButton.addEventListener('click', () => switchTab('about'));
issueTokenButton.addEventListener('click', issueToken);
generateDataButton.addEventListener('click', generateDataPacket);
tlsButton.addEventListener('click', () => applyThreatControl('tls'));
aesButton.addEventListener('click', () => applyThreatControl('aes'));
iamButton.addEventListener('click', () => applyThreatControl('iam'));
edgeButton.addEventListener('click', () => applyThreatControl('edge'));
finishButton.addEventListener('click', finishSimulation);
resetButton.addEventListener('click', initializeSimulation);
clearLogsButton.addEventListener('click', () => {
  logConsole.innerHTML = '<p>[LOGS] Console limpo pelo operador.</p>';
});

setupDropZones();
setStatus('Parado');
updateDashboard();
