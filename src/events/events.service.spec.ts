import { EventsService } from './events.service';

let eventsService;
let mockPrisma;
let mockCacheManager;

mockPrisma = {
  event: {
    create: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
};
mockCacheManager = {
  get: jest.fn(),
  set: jest.fn(),
};

mockCacheManager = {};
eventsService = new EventsService(mockCacheManager, mockPrisma);

describe('EventsService', () => {
  beforeEach(async () => {
    jest.resetAllMocks();
  });

  test('create Method', async () => {
    const mockReturn = 'create Value';
    mockPrisma.event.create.mockReturnValue(mockReturn);

    const createEventDto = {
      eventName: '같이 산책하실분',
      maxSize: 10,
      eventDate: new Date('2023-11-12'),
      signupStartDate: new Date('2023-11-10'),
      signupEndDate: new Date('2023-11-11'),
      location_City: '서울특별시',
      location_District: '종로구',
      content: '재밌게 놀아요',
      category: '산책',
      isDeleted: false,
      isVerified: '🙋‍♀️아무나',
      eventImg: null,
    };

    const createEventData = await eventsService.create(createEventDto);
    expect(createEventData).toEqual(mockReturn);
    expect(mockPrisma.event.creaet).toHaveBeenCalledWith({
      data: createEventDto,
    });
  });

  test('findAll Method', async () => {
    const mockReturn = 'findMany Value';
    mockPrisma.event.findMany.mockReturnValue(mockReturn);

    const page = 1;
    const events = await eventsService.findAll(page);

    expect(events).toBe(mockReturn);
    expect(eventsService.mockPrisma.event.findMany).toHaveBeenCalledTimes(1);
  });

  test('findOne Method', async () => {
    const mockReturn = 'findOne Value';
    mockPrisma.event.findUnique.mockReturn(mockReturn);

    const result = await eventsService.findOne(1);
    expect(result).toEqual(mockReturn);
  });

  test('findOne NotFoundException', async () => {
    mockPrisma.event.findUnique.mockReturnValue(null);
    try {
      await eventsService.findOne(12345);
    } catch (err) {
      expect(eventsService.findOne).toHaveBeenCalledTimes(1);
      expect(eventsService.findOne).toHaveBeenCalledWith(12345);

      expect(err.message).toEqual(`12345번 이벤트가 없습니다`);
    }
  });
});
