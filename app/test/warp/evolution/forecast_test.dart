import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/engine.dart';
import 'package:lxbox/services/evolution/settings.dart';

void main() {
  EvolutionSettings settings({
    int generations = 2,
    int budget = 100,
    List<int> rungs = const [1],
  }) =>
      EvolutionSettings(
        populationSize: 6,
        maxGenerations: generations,
        maxRequests: budget,
        rungAttempts: rungs,
      );

  test('без наблюдений сохраняется худшая оценка цены запроса', () {
    final forecast = EvolutionForecast.estimate(
      settings: settings(budget: 30),
      requestsUsed: 0,
      observedVerdicts: 0,
      paidVerdicts: 0,
      activeTime: Duration.zero,
      worstCaseRequestsPerVerdict: 3,
    );

    expect(forecast.plannedVerdicts, 12);
    expect(forecast.requestsPerVerdict, 3);
    expect(forecast.projectedRequests, 36);
    expect(forecast.budgetCappedRequests, 30);
    expect(forecast.generationsWithinBudget, 1);
    expect(forecast.budgetLimited, isTrue);
    expect(forecast.eta, isNull);
  });

  test('смешанная цена и бесплатная диагностика не искажают остаток и ETA', () {
    final forecast = EvolutionForecast.estimate(
      settings: settings(),
      requestsUsed: 10,
      observedVerdicts: 6,
      paidVerdicts: 4,
      activeTime: const Duration(seconds: 4),
      worstCaseRequestsPerVerdict: 3,
    );

    expect(forecast.requestsPerVerdict, 2.5);
    expect(forecast.remainingVerdicts, 6);
    expect(forecast.projectedRequests, 25);
    expect(forecast.budgetCappedRequests, 25);
    expect(forecast.generationsWithinBudget, 2);
    expect(forecast.budgetLimited, isFalse);
    expect(forecast.eta, const Duration(seconds: 4));
  });

  test('нулевая цена не делит прогноз, но диагностика считается во времени', () {
    final forecast = EvolutionForecast.estimate(
      settings: settings(budget: 18),
      requestsUsed: 0,
      observedVerdicts: 6,
      paidVerdicts: 0,
      activeTime: const Duration(seconds: 6),
      worstCaseRequestsPerVerdict: 3,
    );

    expect(forecast.requestsPerVerdict, 3);
    expect(forecast.remainingVerdicts, 6);
    expect(forecast.projectedRequests, 18);
    expect(forecast.eta, const Duration(seconds: 6));
  });

  test('бюджет ограничивает прогноз и ETA доступными вердиктами', () {
    final forecast = EvolutionForecast.estimate(
      settings: settings(budget: 10),
      requestsUsed: 8,
      observedVerdicts: 4,
      paidVerdicts: 4,
      activeTime: const Duration(seconds: 4),
      worstCaseRequestsPerVerdict: 3,
    );

    expect(forecast.requestsPerVerdict, 2);
    expect(forecast.projectedRequests, 24);
    expect(forecast.budgetCappedRequests, 10);
    expect(forecast.generationsWithinBudget, 0);
    expect(forecast.budgetLimited, isTrue);
    expect(forecast.eta, const Duration(seconds: 1));
  });

  test('уже превышенный бюджет не обрезается ниже фактических затрат', () {
    final forecast = EvolutionForecast.estimate(
      settings: settings(budget: 10),
      requestsUsed: 12,
      observedVerdicts: 4,
      paidVerdicts: 4,
      activeTime: const Duration(seconds: 4),
      worstCaseRequestsPerVerdict: 3,
    );

    expect(forecast.projectedRequests, 36);
    expect(forecast.budgetCappedRequests, 12);
    expect(forecast.budgetLimited, isTrue);
    expect(forecast.eta, isNull);
  });

  test('оценщик вердиктов сохраняет successive halving и множитель запросов', () {
    final configured = settings(
      generations: 3,
      rungs: const [1, 2],
    );

    expect(estimateVerdictsPerGeneration(configured), 12);
    expect(estimateVerdicts(configured), 36);
    expect(estimateRequests(configured, requestsPerVerdict: 3), 108);
  });
}
